//! Variable type extraction for call graph construction.
//!
//! This module contains `FileParseResult` and all per-language VarType extraction
//! functions. Each `extract_*_var_types` function walks a tree-sitter AST to find
//! variable type information (constructor calls, annotations, parameters, literals).
//!
//! Also contains Python-specific definition/call extraction (`extract_python_definitions`,
//! `extract_python_calls`, `parse_python_call`).

use std::collections::{HashMap, HashSet};
use std::path::Path;

use super::cross_file_types::{CallSite, CallType, ClassDef, FuncDef, ImportDef, VarType};
use super::languages::base::{get_node_text, walk_tree};
use super::types::parse_source;

// =============================================================================
// FEATURE-1 d.5 (Part A): declared-return-type propagation helpers
// =============================================================================
//
// For statically-typed languages (go, rust, java, typescript, kotlin, csharp,
// swift) an assignment whose RHS is a plain call — `x = f()` — makes `x` carry
// the DECLARED RETURN TYPE of `f` (Medium confidence, `source = "return"`). This
// generalises the pre-existing luau `fn_return` pass (see
// `extract_lua_like_var_types`) to the other declared-return languages so that
// `x = make(); x.method()` resolves `x.method` type-scoped instead of leaving the
// receiver untyped. Propagation is single-hop and per-file (no whole-program
// dataflow): the callee's return type is only known when the callee is declared
// in the same file, matching the luau precedent.

/// Record a function's declared return type into a `simple name -> Option<type>`
/// map. A simple name that maps to two DIFFERENT return types is marked ambiguous
/// (`None`) and is never applied downstream. Mirrors the luau `fn_return` logic.
fn record_fn_return(map: &mut HashMap<String, Option<String>>, name: String, rtype: String) {
    map.entry(name)
        .and_modify(|e| {
            if e.as_deref() != Some(rtype.as_str()) {
                *e = None;
            }
        })
        .or_insert(Some(rtype));
}

/// Resolve a callee simple name to its unambiguous declared return type, if any.
fn lookup_fn_return<'a>(
    map: &'a HashMap<String, Option<String>>,
    callee: &str,
) -> Option<&'a str> {
    match map.get(callee) {
        Some(Some(rt)) => Some(rt.as_str()),
        _ => None,
    }
}

// =============================================================================
// FileParseResult
// =============================================================================

/// Result of parsing a single file for functions, classes, imports, and calls.
#[derive(Debug, Default)]
pub(crate) struct FileParseResult {
    /// Functions found in this file.
    pub(crate) funcs: Vec<FuncDef>,
    /// Classes found in this file.
    pub(crate) classes: Vec<ClassDef>,
    /// Imports found in this file.
    pub(crate) imports: Vec<ImportDef>,
    /// Calls found in this file, indexed by caller function name.
    pub(crate) calls: HashMap<String, Vec<CallSite>>,
    /// Variable type information extracted from assignments and annotations.
    pub(crate) var_types: Vec<VarType>,
    /// Error message if parsing failed.
    pub(crate) error: Option<String>,
}

// =============================================================================
// Python extraction
// =============================================================================

/// Extract functions, classes, imports, and calls from a Python source file.
pub(crate) fn extract_python_definitions(source: &str, _file_path: &Path) -> FileParseResult {
    let mut result = FileParseResult::default();

    // Parse the source
    let tree = match parse_source(source, "python") {
        Ok(t) => t,
        Err(e) => {
            result.error = Some(e.to_string());
            return result;
        }
    };

    let source_bytes = source.as_bytes();
    let root = tree.root_node();

    // BUG-5 (cross-command-consistency-v1): collect the set of locally-defined
    // function and class names up-front so the call-extractor can recognise
    // function-as-value uses (e.g. `get_converter=_make_timedelta`) and emit
    // `CallType::Ref` edges. Without this, `tldr impact` reports
    // "exported but no callers" for any function that is only used as a value
    // inside the same project — yet `tldr references` finds the use trivially.
    let mut defined_names: HashSet<String> = HashSet::new();
    for node in walk_tree(root) {
        match node.kind() {
            "function_definition" | "class_definition" => {
                if let Some(name_node) = node.child_by_field_name("name") {
                    defined_names.insert(get_node_text(&name_node, source_bytes).to_string());
                }
            }
            _ => {}
        }
    }

    // One-pass extraction for structure and calls.
    for node in walk_tree(root) {
        match node.kind() {
            "import_statement" => {
                // import X or import X as Y
                if let Some(import_def) =
                    super::imports::parse_python_import_statement(&node, source_bytes)
                {
                    result.imports.push(import_def);
                }
            }
            "import_from_statement" => {
                // from X import Y
                if let Some(import_def) =
                    super::imports::parse_python_from_import(&node, source_bytes)
                {
                    result.imports.push(import_def);
                }
            }
            "class_definition" => {
                if let Some(name_node) = node.child_by_field_name("name") {
                    let class_name = get_node_text(&name_node, source_bytes).to_string();
                    let line = node.start_position().row as u32 + 1;
                    let end_line = node.end_position().row as u32 + 1;

                    // Extract base classes
                    let mut bases = Vec::new();
                    if let Some(arg_list) = node.child_by_field_name("superclasses") {
                        for i in 0..arg_list.named_child_count() {
                            if let Some(base) = arg_list.named_child(i) {
                                bases.push(get_node_text(&base, source_bytes).to_string());
                            }
                        }
                    }

                    // Collect method names from class body
                    let mut methods = Vec::new();
                    if let Some(body) = node.child_by_field_name("body") {
                        for i in 0..body.named_child_count() {
                            if let Some(child) = body.named_child(i) {
                                if child.kind() == "function_definition" {
                                    if let Some(fn_name) = child.child_by_field_name("name") {
                                        methods.push(
                                            get_node_text(&fn_name, source_bytes).to_string(),
                                        );
                                    }
                                }
                            }
                        }
                    }

                    // BUG-5: extract function-as-value Refs from class-body
                    // field initialisers (e.g. `attr = some(callback=_helper)`).
                    // This makes class-body field references discoverable to
                    // `tldr impact`. The caller name is the class name itself
                    // (matches the existing python.rs handler convention).
                    if let Some(body) = node.child_by_field_name("body") {
                        let mut class_calls = Vec::new();
                        for i in 0..body.named_child_count() {
                            if let Some(child) = body.named_child(i) {
                                if matches!(
                                    child.kind(),
                                    "function_definition"
                                        | "class_definition"
                                        | "decorated_definition"
                                ) {
                                    continue;
                                }
                                collect_python_value_refs(
                                    &child,
                                    source_bytes,
                                    &class_name,
                                    &defined_names,
                                    &mut class_calls,
                                );
                            }
                        }
                        if !class_calls.is_empty() {
                            result
                                .calls
                                .entry(class_name.clone())
                                .or_default()
                                .extend(class_calls);
                        }
                    }

                    result
                        .classes
                        .push(ClassDef::new(class_name, line, end_line, methods, bases));
                }
            }
            "function_definition" => {
                if let Some(name_node) = node.child_by_field_name("name") {
                    let func_name = get_node_text(&name_node, source_bytes).to_string();
                    let line = node.start_position().row as u32 + 1;
                    let end_line = node.end_position().row as u32 + 1;

                    // Check if this is a method (directly inside a class body).
                    let mut class_name = None;
                    let mut parent = node.parent();
                    while let Some(p) = parent {
                        if p.kind() == "block" {
                            if let Some(gp) = p.parent() {
                                if gp.kind() == "class_definition" {
                                    if let Some(cn) = gp.child_by_field_name("name") {
                                        class_name =
                                            Some(get_node_text(&cn, source_bytes).to_string());
                                    }
                                }
                            }
                            break;
                        }
                        parent = p.parent();
                    }

                    // Determine the caller name: qualified for methods, simple for top-level functions
                    let caller_name = if let Some(ref cn) = class_name {
                        result.funcs.push(FuncDef::method(
                            func_name.clone(),
                            cn.clone(),
                            line,
                            end_line,
                        ));
                        format!("{}.{}", cn, func_name)
                    } else {
                        result
                            .funcs
                            .push(FuncDef::function(func_name.clone(), line, end_line));
                        func_name.clone()
                    };

                    // Extract calls within this function using the qualified caller name
                    let mut calls = extract_python_calls(&node, source_bytes, &caller_name);

                    // BUG-5: also extract function-as-value (Ref) edges so
                    // `tldr impact` can find higher-order use of locally
                    // defined functions (return / assignment / kwarg /
                    // positional argument).
                    collect_python_value_refs(
                        &node,
                        source_bytes,
                        &caller_name,
                        &defined_names,
                        &mut calls,
                    );

                    // callgraph-dataflow-issues-v1 (#39): when this
                    // function is wrapped in `decorated_definition`, the
                    // sibling `decorator` nodes ARE NOT children of the
                    // function_definition. Walk them explicitly so
                    // `@register(my_handler)` emits the Direct call to
                    // `register` AND the Ref edge to the identifier
                    // argument `my_handler` (mirroring the function body
                    // extraction). Without this, `tldr impact my_handler`
                    // returned `caller_count: 0` even though the
                    // decorator references were trivially visible to
                    // `tldr references` / `tldr search`.
                    if let Some(parent) = node.parent() {
                        if parent.kind() == "decorated_definition" {
                            for i in 0..parent.named_child_count() {
                                if let Some(sib) = parent.named_child(i) {
                                    if sib.kind() != "decorator" {
                                        continue;
                                    }
                                    let dec_calls =
                                        extract_python_calls(&sib, source_bytes, &caller_name);
                                    calls.extend(dec_calls);
                                    collect_python_value_refs(
                                        &sib,
                                        source_bytes,
                                        &caller_name,
                                        &defined_names,
                                        &mut calls,
                                    );
                                }
                            }
                        }
                    }

                    if !calls.is_empty() {
                        result.calls.insert(caller_name, calls);
                    }
                }
            }
            _ => {}
        }
    }

    // Extract VarType information from the tree before dropping it
    result.var_types = extract_python_var_types(&tree, source_bytes);

    // Explicitly drop the tree to free memory (per spec)
    drop(tree);

    result
}

/// BUG-5: walk a node and collect identifier-as-value uses that resolve to
/// locally-defined functions/classes as `CallType::Ref` call sites.
///
/// "function-as-value" means an identifier appears outside of the
/// `function` field of a `call` node — e.g. `return _helper`, `fn = _helper`,
/// `map(_helper, ...)`, `kw=_helper`, etc. These uses must produce edges so
/// that `tldr impact` returns the same callers that `tldr references` finds.
///
/// Each defined name is added at most once per (caller, target) to keep the
/// edge set bounded; the line is the first occurrence.
fn collect_python_value_refs(
    root_node: &tree_sitter::Node,
    source: &[u8],
    caller: &str,
    defined_names: &HashSet<String>,
    sink: &mut Vec<CallSite>,
) {
    if defined_names.is_empty() {
        return;
    }
    let mut emitted: HashSet<String> = HashSet::new();
    for node in walk_tree(*root_node) {
        if node.kind() != "identifier" {
            continue;
        }
        let name = get_node_text(&node, source);
        if !defined_names.contains(name) {
            continue;
        }
        let parent = match node.parent() {
            Some(p) => p,
            None => continue,
        };
        // Skip the identifier-form of a call's `function` field — that
        // is the regular "Direct" / "Method" call path handled by
        // parse_python_call.
        if parent.kind() == "call"
            && parent.child_by_field_name("function").as_ref() == Some(&node)
        {
            continue;
        }
        // Skip definition sites: `def name(...)` and `class name:`.
        if matches!(parent.kind(), "function_definition" | "class_definition")
            && parent.child_by_field_name("name").as_ref() == Some(&node)
        {
            continue;
        }
        // Skip attribute accesses where this identifier is the
        // attribute name (`obj.name` — that's a method/attr access,
        // not a free reference to the local function).
        if parent.kind() == "attribute"
            && parent.child_by_field_name("attribute").as_ref() == Some(&node)
        {
            continue;
        }
        // Skip parameter lists — `def f(x):` parameters are not Refs.
        if matches!(
            parent.kind(),
            "parameters" | "default_parameter" | "typed_parameter" | "typed_default_parameter"
        ) {
            continue;
        }
        // Dedup per (caller, target) to keep the edge set bounded.
        if !emitted.insert(name.to_string()) {
            continue;
        }
        let line = node.start_position().row as u32 + 1;
        sink.push(CallSite::new(
            caller.to_string(),
            name.to_string(),
            CallType::Ref,
            Some(line),
            None,
            None,
            None,
        ));
    }
}

/// Extract calls from a Python function body.
pub(crate) fn extract_python_calls(
    func_node: &tree_sitter::Node,
    source: &[u8],
    caller: &str,
) -> Vec<CallSite> {
    let mut calls = Vec::new();

    // Walk the function body looking for call expressions
    for node in walk_tree(*func_node) {
        if node.kind() == "call" {
            if let Some(call_site) = parse_python_call(&node, source, caller) {
                calls.push(call_site);
            }
        }
    }

    calls
}

/// Parse a Python call expression into a CallSite.
fn parse_python_call(node: &tree_sitter::Node, source: &[u8], caller: &str) -> Option<CallSite> {
    let line = node.start_position().row as u32 + 1;
    let column = node.start_position().column as u32 + 1;

    // Get the function/method being called
    let func_node = node.child_by_field_name("function")?;

    match func_node.kind() {
        "identifier" => {
            // Simple call: foo()
            let target = get_node_text(&func_node, source).to_string();
            Some(CallSite::new(
                caller.to_string(),
                target,
                CallType::Direct,
                Some(line),
                Some(column),
                None,
                None,
            ))
        }
        "attribute" => {
            // Method or attribute call: obj.method() or module.func()
            let object_node = func_node.child_by_field_name("object")?;
            let attr_node = func_node.child_by_field_name("attribute")?;

            let receiver = get_node_text(&object_node, source).to_string();
            let target = get_node_text(&attr_node, source).to_string();

            // Determine call type based on receiver
            // If receiver is a simple identifier, it could be either:
            // - A module (import-based call): json.loads()
            // - An object (method call): user.save()
            // We'll mark it as Method and resolve later during import resolution
            Some(CallSite::new(
                caller.to_string(),
                target,
                CallType::Method,
                Some(line),
                Some(column),
                Some(receiver),
                None, // receiver_type will be filled during type resolution
            ))
        }
        _ => None,
    }
}

/// Determine the enclosing function scope for a tree-sitter node.
///
/// Walks up the parent chain to find the nearest `function_definition` ancestor.
/// Returns `Some(function_name)` if found, `None` for module-level scope.
pub(crate) fn enclosing_function_scope(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "function_definition" {
            if let Some(name_node) = parent.child_by_field_name("name") {
                return Some(get_node_text(&name_node, source).to_string());
            }
        }
        current = parent.parent();
    }
    None
}

// =============================================================================
// Python VarType extraction
// =============================================================================

/// Extract VarType entries from a Python source tree.
///
/// Walks the AST to find:
/// - **Constructor assignments**: `x = Foo()` -> VarType { source: "assignment" }
/// - **Annotated assignments**: `x: Foo` or `x: Foo = ...` -> VarType { source: "annotation" }
/// - **Parameter annotations**: `def f(x: Foo)` -> VarType { source: "parameter" }
///
/// Scope is determined by the enclosing function definition, or None for module-level.
pub(crate) fn extract_python_var_types(tree: &tree_sitter::Tree, source: &[u8]) -> Vec<VarType> {
    let mut var_types = Vec::new();
    let root = tree.root_node();

    for node in walk_tree(root) {
        match node.kind() {
            // Pattern 1: x = Foo() -- constructor assignment
            // Pattern 1b: x = {} / [] / "" / () -- builtin literal assignment
            "assignment" => {
                // Left side should be a simple identifier
                let left = match node.child_by_field_name("left") {
                    Some(n) if n.kind() == "identifier" => n,
                    _ => continue,
                };
                let right = match node.child_by_field_name("right") {
                    Some(n) => n,
                    None => continue,
                };

                let var_name = get_node_text(&left, source).to_string();
                if var_name.is_empty() {
                    continue;
                }
                let line = node.start_position().row as u32 + 1;
                let scope = enclosing_function_scope(&node, source);

                match right.kind() {
                    "call" => {
                        // The call's function should be a simple identifier
                        let func_node = match right.child_by_field_name("function") {
                            Some(n) if n.kind() == "identifier" => n,
                            _ => continue,
                        };
                        let type_name = get_node_text(&func_node, source).to_string();

                        // Check for lowercase builtin constructors: dict(), list(), set(), etc.
                        if type_name.chars().next().is_none_or(|c| c.is_lowercase()) {
                            match type_name.as_str() {
                                "dict" | "list" | "set" | "tuple" | "frozenset" | "str"
                                | "bytes" | "bytearray" | "int" | "float" | "bool" | "complex" => {
                                    var_types.push(VarType::new_with_scope(
                                        var_name,
                                        type_name,
                                        "constructor",
                                        line,
                                        scope,
                                    ));
                                }
                                _ => {} // Skip other lowercase calls
                            }
                            continue;
                        }

                        // Capitalized call -- likely a class constructor: Foo()
                        var_types.push(VarType::new_with_scope(
                            var_name,
                            type_name,
                            "assignment",
                            line,
                            scope,
                        ));
                    }
                    // Builtin literal types
                    "dictionary" | "dictionary_comprehension" => {
                        var_types.push(VarType::new_with_scope(
                            var_name,
                            "dict".to_string(),
                            "literal",
                            line,
                            scope,
                        ));
                    }
                    "list" | "list_comprehension" => {
                        var_types.push(VarType::new_with_scope(
                            var_name,
                            "list".to_string(),
                            "literal",
                            line,
                            scope,
                        ));
                    }
                    "string" | "concatenated_string" => {
                        var_types.push(VarType::new_with_scope(
                            var_name,
                            "str".to_string(),
                            "literal",
                            line,
                            scope,
                        ));
                    }
                    "tuple" => {
                        var_types.push(VarType::new_with_scope(
                            var_name,
                            "tuple".to_string(),
                            "literal",
                            line,
                            scope,
                        ));
                    }
                    "set" | "set_comprehension" => {
                        var_types.push(VarType::new_with_scope(
                            var_name,
                            "set".to_string(),
                            "literal",
                            line,
                            scope,
                        ));
                    }
                    "integer" => {
                        var_types.push(VarType::new_with_scope(
                            var_name,
                            "int".to_string(),
                            "literal",
                            line,
                            scope,
                        ));
                    }
                    "float" => {
                        var_types.push(VarType::new_with_scope(
                            var_name,
                            "float".to_string(),
                            "literal",
                            line,
                            scope,
                        ));
                    }
                    "true" | "false" => {
                        var_types.push(VarType::new_with_scope(
                            var_name,
                            "bool".to_string(),
                            "literal",
                            line,
                            scope,
                        ));
                    }
                    _ => {}
                }
            }

            // Pattern 2: x: Foo or x: Foo = ... -- type annotation
            "type" => {
                // A "type" node inside an expression_statement or assignment
                // represents a type annotation.
                // For `x: Foo`, tree-sitter produces:
                //   expression_statement > type > identifier(x) + type(Foo)
                // For `x: Foo = val`, tree-sitter produces:
                //   assignment > type > identifier(x) + type(Foo)  [left side]
                //
                // We handle this by looking at the parent context.
                // Actually, tree-sitter Python handles annotations differently.
                // Let's handle it via the parent node patterns.
            }

            // Pattern 2 (actual): Annotated assignments and standalone annotations
            // tree-sitter-python produces different node types:
            // - `x: int = 5` -> expression_statement containing type annotation
            // We catch typed_parameter for function params separately below.
            "expression_statement" => {
                // Check if this contains a type annotation: `x: Type`
                // tree-sitter-python emits this as an expression_statement
                // containing a "type" child with annotation syntax.
                //
                // Actually, annotations in tree-sitter-python are handled as:
                // expression_statement > assignment with type annotation
                // Let's check the first child.
                if node.named_child_count() == 1 {
                    if let Some(child) = node.named_child(0) {
                        if child.kind() == "type" {
                            // Standalone annotation: `x: Foo`
                            // The type node has two children: the name and the type
                            if let (Some(name_node), Some(type_node)) =
                                (child.child_by_field_name("type"), child.child(0))
                            {
                                // This is tricky - let me handle it more carefully
                                let _ = (name_node, type_node);
                            }
                        }
                    }
                }
            }

            // Pattern 3: def f(x: Foo) -- typed parameter
            "typed_parameter" => {
                // typed_parameter has a name (identifier) and a type
                let name_node = match node.child_by_field_name("name") {
                    Some(n) => n,
                    None => {
                        // Fallback: first child might be the name
                        match node.child(0) {
                            Some(n) if n.kind() == "identifier" => n,
                            _ => continue,
                        }
                    }
                };
                let type_node = match node.child_by_field_name("type") {
                    Some(n) => n,
                    None => continue,
                };

                let var_name = get_node_text(&name_node, source).to_string();
                let type_name = get_node_text(&type_node, source).to_string();
                let line = node.start_position().row as u32 + 1;

                // Skip 'self' and 'cls' parameters
                if var_name == "self" || var_name == "cls" {
                    continue;
                }

                // Determine scope: the enclosing function
                let scope = enclosing_function_scope(&node, source);

                var_types.push(VarType::new_with_scope(
                    var_name,
                    type_name,
                    "parameter",
                    line,
                    scope,
                ));
            }

            // Pattern 3b: def f(x: Foo = default_val) -- typed parameter with default
            "typed_default_parameter" => {
                let name_node = match node.child_by_field_name("name") {
                    Some(n) => n,
                    None => match node.child(0) {
                        Some(n) if n.kind() == "identifier" => n,
                        _ => continue,
                    },
                };
                let type_node = match node.child_by_field_name("type") {
                    Some(n) => n,
                    None => continue,
                };

                let var_name = get_node_text(&name_node, source).to_string();
                let type_name = get_node_text(&type_node, source).to_string();
                let line = node.start_position().row as u32 + 1;

                if var_name == "self" || var_name == "cls" {
                    continue;
                }

                let scope = enclosing_function_scope(&node, source);

                var_types.push(VarType::new_with_scope(
                    var_name,
                    type_name,
                    "parameter",
                    line,
                    scope,
                ));
            }

            _ => {}
        }
    }

    var_types
}

// =============================================================================
// Go VarType extraction
// =============================================================================

/// Determine the enclosing function scope for a Go AST node.
///
/// Go uses `function_declaration` (top-level funcs) and `method_declaration` (receiver methods).
/// For methods, the scope is `ReceiverType.MethodName`.
pub(crate) fn enclosing_go_function_scope(
    node: &tree_sitter::Node,
    source: &[u8],
) -> Option<String> {
    let mut current = node.parent();
    while let Some(parent) = current {
        match parent.kind() {
            "function_declaration" => {
                if let Some(name_node) = parent.child_by_field_name("name") {
                    return Some(get_node_text(&name_node, source).to_string());
                }
            }
            "method_declaration" => {
                let method_name = parent
                    .child_by_field_name("name")
                    .map(|n| get_node_text(&n, source).to_string());
                if let Some(name) = method_name {
                    // Try to get receiver type for full scope like "Foo.Method"
                    if let Some(receiver_list) = parent.child_by_field_name("receiver") {
                        for i in 0..receiver_list.named_child_count() {
                            if let Some(param) = receiver_list.named_child(i) {
                                if param.kind() == "parameter_declaration" {
                                    if let Some(type_node) = param.child_by_field_name("type") {
                                        let type_text = get_node_text(&type_node, source);
                                        let receiver_type = type_text.trim_start_matches('*');
                                        return Some(format!("{}.{}", receiver_type, name));
                                    }
                                }
                            }
                        }
                    }
                    return Some(name);
                }
            }
            _ => {}
        }
        current = parent.parent();
    }
    None
}

/// Extract VarType entries from a Go source tree.
///
/// Walks the AST to find:
/// - **Short var declaration with composite literal**: `x := Foo{...}` -> VarType { source: "assignment" }
/// - **Short var declaration with constructor call**: `x := NewFoo()` -> VarType { source: "assignment" }
/// - **Var declaration with type**: `var x Foo` -> VarType { source: "annotation" }
/// - **Function/method parameters with types**: `func f(x Foo)` -> VarType { source: "parameter" }
/// - **Method receiver parameters**: `func (f *Foo) Method()` -> VarType { source: "parameter" }
///
/// Builtin types (map, slice, array, chan, string, int, etc.) produce "literal" source to
/// enable the FP defense layers (blocklist + ambiguity gate) for Go.
/// FEATURE-1 d.5 (Part A): normalise a Go result/type node to a bare type name.
/// Handles `T`, `*T`, `pkg.T`, `Generic[...]`; returns `None` for composite
/// result kinds (tuples/slices/maps/func types) which do not denote a single
/// nominal type.
fn go_type_name(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    match node.kind() {
        "type_identifier" => Some(get_node_text(node, source).to_string()),
        "pointer_type" => node.named_child(0).and_then(|n| go_type_name(&n, source)),
        "qualified_type" => node
            .child_by_field_name("name")
            .map(|n| get_node_text(&n, source).to_string())
            .or_else(|| {
                let text = get_node_text(node, source).to_string();
                text.rsplit('.').next().map(|s| s.to_string())
            }),
        "generic_type" => node
            .child_by_field_name("type")
            .or_else(|| node.named_child(0))
            .and_then(|n| go_type_name(&n, source)),
        _ => None,
    }
}

/// FEATURE-1 d.5 (Part A): build the per-file `func/method simple name -> declared
/// return type` map for Go.
fn go_fn_return_map(
    root: tree_sitter::Node,
    source: &[u8],
    builtins: &[&str],
) -> HashMap<String, Option<String>> {
    let mut map: HashMap<String, Option<String>> = HashMap::new();
    for node in walk_tree(root) {
        if node.kind() != "function_declaration" && node.kind() != "method_declaration" {
            continue;
        }
        let name = match node.child_by_field_name("name") {
            Some(n) => get_node_text(&n, source).to_string(),
            None => continue,
        };
        let result = match node.child_by_field_name("result") {
            Some(r) => r,
            None => continue,
        };
        if let Some(rt) = go_type_name(&result, source) {
            if !rt.is_empty() && !builtins.contains(&rt.as_str()) {
                record_fn_return(&mut map, name, rt);
            }
        }
    }
    map
}

pub(crate) fn extract_go_var_types(tree: &tree_sitter::Tree, source: &[u8]) -> Vec<VarType> {
    let mut var_types = Vec::new();
    let root = tree.root_node();

    // Go builtin types that should not match project classes
    let go_builtin_types = [
        "string",
        "int",
        "int8",
        "int16",
        "int32",
        "int64",
        "uint",
        "uint8",
        "uint16",
        "uint32",
        "uint64",
        "uintptr",
        "float32",
        "float64",
        "complex64",
        "complex128",
        "bool",
        "byte",
        "rune",
        "error",
        "any",
    ];

    // FEATURE-1 d.5 (Part A): declared return types for same-file funcs/methods.
    let fn_return = go_fn_return_map(root, source, &go_builtin_types);

    for node in walk_tree(root) {
        match node.kind() {
            // Pattern 1: x := Foo{...} or x := NewFoo()
            // short_var_declaration has left (expression_list) and right (expression_list)
            "short_var_declaration" => {
                let left = match node.child_by_field_name("left") {
                    Some(n) => n,
                    None => continue,
                };
                let right = match node.child_by_field_name("right") {
                    Some(n) => n,
                    None => continue,
                };

                // Right side must have exactly 1 expression
                if right.named_child_count() != 1 {
                    continue;
                }

                let val_node = match right.named_child(0) {
                    Some(n) => n,
                    None => continue,
                };

                let line = node.start_position().row as u32 + 1;
                let scope = enclosing_go_function_scope(&node, source);

                // Multi-return: x, err := NewFoo() or x, ok := val.(Foo)
                if left.named_child_count() >= 2 {
                    let var_node = match left.named_child(0) {
                        Some(n) if n.kind() == "identifier" => n,
                        _ => continue,
                    };
                    let var_name = get_node_text(&var_node, source).to_string();
                    if var_name == "_" {
                        continue;
                    }

                    match val_node.kind() {
                        "call_expression" => {
                            if let Some(func_node) = val_node.child_by_field_name("function") {
                                let func_text = get_node_text(&func_node, source).to_string();
                                let base_name = func_text.rsplit('.').next().unwrap_or(&func_text);
                                if base_name.starts_with("New") && base_name.len() > 3 {
                                    let type_name = &base_name[3..];
                                    if !type_name.is_empty()
                                        && type_name
                                            .chars()
                                            .next()
                                            .is_some_and(|c| c.is_uppercase())
                                    {
                                        var_types.push(VarType::new_with_scope(
                                            var_name,
                                            type_name.to_string(),
                                            "assignment",
                                            line,
                                            scope,
                                        ));
                                    }
                                } else if base_name.chars().next().is_some_and(|c| c.is_uppercase())
                                {
                                    var_types.push(VarType::new_with_scope(
                                        var_name,
                                        base_name.to_string(),
                                        "assignment",
                                        line,
                                        scope,
                                    ));
                                }
                            }
                        }
                        "composite_literal" => {
                            if let Some(type_node) = val_node.child_by_field_name("type") {
                                let type_text = get_node_text(&type_node, source).to_string();
                                match type_node.kind() {
                                    "type_identifier" => {
                                        if !go_builtin_types.contains(&type_text.as_str()) {
                                            var_types.push(VarType::new_with_scope(
                                                var_name,
                                                type_text,
                                                "assignment",
                                                line,
                                                scope.clone(),
                                            ));
                                        }
                                    }
                                    "qualified_type" => {
                                        var_types.push(VarType::new_with_scope(
                                            var_name,
                                            type_text,
                                            "assignment",
                                            line,
                                            scope.clone(),
                                        ));
                                    }
                                    _ => {}
                                }
                            }
                        }
                        "type_assertion_expression" => {
                            // x, ok := val.(Foo)
                            if let Some(type_node) = val_node.child_by_field_name("type") {
                                let type_text = get_node_text(&type_node, source).to_string();
                                let clean_type = type_text.trim_start_matches('*').to_string();
                                if !go_builtin_types.contains(&clean_type.as_str()) {
                                    var_types.push(VarType::new_with_scope(
                                        var_name,
                                        clean_type,
                                        "assertion",
                                        line,
                                        scope,
                                    ));
                                }
                            }
                        }
                        _ => {}
                    }
                    continue;
                }

                // Single assignment: x := expr
                if left.named_child_count() != 1 {
                    continue;
                }

                let var_node = match left.named_child(0) {
                    Some(n) if n.kind() == "identifier" => n,
                    _ => continue,
                };

                let var_name = get_node_text(&var_node, source).to_string();
                if var_name == "_" {
                    continue;
                }

                match val_node.kind() {
                    "composite_literal" => {
                        if let Some(type_node) = val_node.child_by_field_name("type") {
                            let type_text = get_node_text(&type_node, source).to_string();
                            match type_node.kind() {
                                "type_identifier" => {
                                    if !go_builtin_types.contains(&type_text.as_str()) {
                                        var_types.push(VarType::new_with_scope(
                                            var_name,
                                            type_text,
                                            "assignment",
                                            line,
                                            scope,
                                        ));
                                    }
                                }
                                "qualified_type" => {
                                    var_types.push(VarType::new_with_scope(
                                        var_name,
                                        type_text,
                                        "assignment",
                                        line,
                                        scope,
                                    ));
                                }
                                "map_type" | "slice_type" | "array_type" => {
                                    let builtin_name = match type_node.kind() {
                                        "map_type" => "map",
                                        "slice_type" => "slice",
                                        "array_type" => "array",
                                        _ => "unknown",
                                    };
                                    var_types.push(VarType::new_with_scope(
                                        var_name,
                                        builtin_name.to_string(),
                                        "literal",
                                        line,
                                        scope,
                                    ));
                                }
                                _ => {}
                            }
                        }
                    }
                    "call_expression" => {
                        if let Some(func_node) = val_node.child_by_field_name("function") {
                            let func_text = get_node_text(&func_node, source).to_string();
                            let base_name = func_text.rsplit('.').next().unwrap_or(&func_text);
                            if base_name.starts_with("New") && base_name.len() > 3 {
                                let type_name = &base_name[3..];
                                if !type_name.is_empty()
                                    && type_name.chars().next().is_some_and(|c| c.is_uppercase())
                                {
                                    var_types.push(VarType::new_with_scope(
                                        var_name,
                                        type_name.to_string(),
                                        "assignment",
                                        line,
                                        scope,
                                    ));
                                }
                            } else if base_name.chars().next().is_some_and(|c| c.is_uppercase()) {
                                var_types.push(VarType::new_with_scope(
                                    var_name,
                                    base_name.to_string(),
                                    "assignment",
                                    line,
                                    scope,
                                ));
                            } else if let Some(rt) = lookup_fn_return(&fn_return, base_name) {
                                // FEATURE-1 d.5 (Part A): x := makeWidget() where
                                // makeWidget() returns a declared nominal type.
                                var_types.push(VarType::new_with_scope(
                                    var_name,
                                    rt.to_string(),
                                    "return",
                                    line,
                                    scope,
                                ));
                            }
                        }
                    }
                    "type_assertion_expression" => {
                        // x := val.(Foo)
                        if let Some(type_node) = val_node.child_by_field_name("type") {
                            let type_text = get_node_text(&type_node, source).to_string();
                            let clean_type = type_text.trim_start_matches('*').to_string();
                            if !go_builtin_types.contains(&clean_type.as_str()) {
                                var_types.push(VarType::new_with_scope(
                                    var_name,
                                    clean_type,
                                    "assertion",
                                    line,
                                    scope,
                                ));
                            }
                        }
                    }
                    "interpreted_string_literal" | "raw_string_literal" => {
                        var_types.push(VarType::new_with_scope(
                            var_name,
                            "string".to_string(),
                            "literal",
                            line,
                            scope,
                        ));
                    }
                    "int_literal" => {
                        var_types.push(VarType::new_with_scope(
                            var_name,
                            "int".to_string(),
                            "literal",
                            line,
                            scope,
                        ));
                    }
                    "float_literal" => {
                        var_types.push(VarType::new_with_scope(
                            var_name,
                            "float64".to_string(),
                            "literal",
                            line,
                            scope,
                        ));
                    }
                    "true" | "false" => {
                        var_types.push(VarType::new_with_scope(
                            var_name,
                            "bool".to_string(),
                            "literal",
                            line,
                            scope,
                        ));
                    }
                    _ => {}
                }
            }

            // Pattern 2: var x Foo -- explicit type declaration
            "var_spec" => {
                let name_node = match node.child_by_field_name("name") {
                    Some(n) if n.kind() == "identifier" => n,
                    _ => continue,
                };
                let type_node = match node.child_by_field_name("type") {
                    Some(n) => n,
                    None => continue,
                };

                let var_name = get_node_text(&name_node, source).to_string();
                let type_text = get_node_text(&type_node, source).to_string();
                let line = node.start_position().row as u32 + 1;
                let scope = enclosing_go_function_scope(&node, source);

                // Only track non-builtin types
                if !go_builtin_types.contains(&type_text.as_str()) {
                    var_types.push(VarType::new_with_scope(
                        var_name,
                        type_text,
                        "annotation",
                        line,
                        scope,
                    ));
                }
            }

            // Pattern 3: func f(x Foo) -- function parameter with type
            "parameter_declaration" => {
                // Skip if inside a receiver (handled as part of method_declaration scope)
                // Check parent: if it's a parameter_list that's a "receiver" field, skip
                if let Some(param_list) = node.parent() {
                    if let Some(method_decl) = param_list.parent() {
                        if method_decl.kind() == "method_declaration" {
                            if let Some(receiver) = method_decl.child_by_field_name("receiver") {
                                if receiver.id() == param_list.id() {
                                    // This is a receiver parameter -- still extract it
                                    // but with special handling
                                    if let (Some(name_node), Some(type_node)) = (
                                        node.child_by_field_name("name"),
                                        node.child_by_field_name("type"),
                                    ) {
                                        let var_name =
                                            get_node_text(&name_node, source).to_string();
                                        let type_text =
                                            get_node_text(&type_node, source).to_string();
                                        // Strip pointer: *Foo -> Foo
                                        let clean_type =
                                            type_text.trim_start_matches('*').to_string();
                                        let line = node.start_position().row as u32 + 1;
                                        let scope = enclosing_go_function_scope(&node, source);
                                        if !go_builtin_types.contains(&clean_type.as_str()) {
                                            var_types.push(VarType::new_with_scope(
                                                var_name,
                                                clean_type,
                                                "parameter",
                                                line,
                                                scope,
                                            ));
                                        }
                                    }
                                    continue;
                                }
                            }
                        }
                    }
                }

                // Regular function parameter
                let name_node = match node.child_by_field_name("name") {
                    Some(n) if n.kind() == "identifier" => n,
                    _ => continue,
                };
                let type_node = match node.child_by_field_name("type") {
                    Some(n) => n,
                    None => continue,
                };

                let var_name = get_node_text(&name_node, source).to_string();
                let type_text = get_node_text(&type_node, source).to_string();
                // Strip pointer: *Foo -> Foo
                let clean_type = type_text.trim_start_matches('*').to_string();
                let line = node.start_position().row as u32 + 1;
                let scope = enclosing_go_function_scope(&node, source);

                if !go_builtin_types.contains(&clean_type.as_str()) {
                    var_types.push(VarType::new_with_scope(
                        var_name,
                        clean_type,
                        "parameter",
                        line,
                        scope,
                    ));
                }
            }

            _ => {}
        }
    }

    var_types
}

// =============================================================================
// TypeScript/JavaScript VarType extraction
// =============================================================================

/// Determine the enclosing function scope for a TypeScript/JavaScript AST node.
///
/// Walks parent nodes looking for:
/// - `function_declaration` -> function name
/// - `method_definition` -> `ClassName.methodName` (prepends class name if found)
/// - `arrow_function` / `function_expression` / `function` -> check parent `variable_declarator` for name
///
/// Returns `None` for module-level code (no enclosing function).
pub(crate) fn enclosing_ts_function_scope(
    node: &tree_sitter::Node,
    source: &[u8],
) -> Option<String> {
    let mut current = node.parent();
    while let Some(parent) = current {
        match parent.kind() {
            "function_declaration" => {
                if let Some(name_node) = parent.child_by_field_name("name") {
                    return Some(get_node_text(&name_node, source).to_string());
                }
            }
            "method_definition" => {
                let method_name = parent
                    .child_by_field_name("name")
                    .map(|n| get_node_text(&n, source).to_string());
                if let Some(name) = method_name {
                    // Try to get class name: method_definition > class_body > class_declaration
                    if let Some(class_body) = parent.parent() {
                        if class_body.kind() == "class_body" {
                            if let Some(class_decl) = class_body.parent() {
                                if class_decl.kind() == "class_declaration"
                                    || class_decl.kind() == "class"
                                {
                                    if let Some(class_name_node) =
                                        class_decl.child_by_field_name("name")
                                    {
                                        let class_name = get_node_text(&class_name_node, source);
                                        return Some(format!("{}.{}", class_name, name));
                                    }
                                }
                            }
                        }
                    }
                    return Some(name);
                }
            }
            "arrow_function" | "function_expression" | "function" => {
                // Anonymous -- check if parent is variable_declarator
                if let Some(var_decl) = parent.parent() {
                    if var_decl.kind() == "variable_declarator" {
                        if let Some(name_node) = var_decl.child_by_field_name("name") {
                            return Some(get_node_text(&name_node, source).to_string());
                        }
                    }
                }
                // Truly anonymous -- return None (module scope)
                return None;
            }
            _ => {}
        }
        current = parent.parent();
    }
    None
}

/// Extract VarType entries from a TypeScript/JavaScript source tree.
/// FEATURE-1 d.5 (Part A): normalise a TS type node to a bare nominal name.
fn ts_type_name(type_node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    match type_node.kind() {
        "type_identifier" => Some(get_node_text(type_node, source).to_string()),
        "generic_type" => type_node
            .child_by_field_name("name")
            .map(|n| get_node_text(&n, source).to_string()),
        _ => None,
    }
}

/// FEATURE-1 d.5 (Part A): build the per-file `fn/method simple name -> declared
/// return type` map for TypeScript (`function f(): T` / `method(): T`).
fn ts_fn_return_map(
    root: tree_sitter::Node,
    source: &[u8],
    builtins: &[&str],
) -> HashMap<String, Option<String>> {
    let mut map: HashMap<String, Option<String>> = HashMap::new();
    for node in walk_tree(root) {
        if !matches!(
            node.kind(),
            "function_declaration" | "method_definition" | "function_signature"
        ) {
            continue;
        }
        let name = match node.child_by_field_name("name") {
            Some(n) => get_node_text(&n, source).to_string(),
            None => continue,
        };
        let ret_ann = match node.child_by_field_name("return_type") {
            Some(r) => r,
            None => continue,
        };
        // return_type is a `type_annotation` node; its first named child is the type.
        if let Some(type_node) = ret_ann.named_child(0) {
            if let Some(rt) = ts_type_name(&type_node, source) {
                if !rt.is_empty() && !builtins.contains(&rt.as_str()) {
                    record_fn_return(&mut map, name, rt);
                }
            }
        }
    }
    map
}

pub(crate) fn extract_ts_var_types(tree: &tree_sitter::Tree, source: &[u8]) -> Vec<VarType> {
    let mut var_types = Vec::new();
    let root = tree.root_node();

    // TS/JS builtin types that should not match project classes
    let ts_builtin_types = [
        "string",
        "number",
        "boolean",
        "bigint",
        "symbol",
        "undefined",
        "null",
        "void",
        "never",
        "any",
        "unknown",
        "object",
        "String",
        "Number",
        "Boolean",
        "Function",
        "Object",
        "Array",
        "Promise",
        "Map",
        "Set",
        "RegExp",
        "Date",
        "Error",
        "Symbol",
    ];

    // FEATURE-1 d.5 (Part A): declared return types for same-file fns/methods.
    let fn_return = ts_fn_return_map(root, source, &ts_builtin_types);

    for node in walk_tree(root) {
        match node.kind() {
            // Pattern 1: const x = new Foo() / let x: Type = expr / let x: Type
            "variable_declarator" => {
                let name_node = match node.child_by_field_name("name") {
                    Some(n) if n.kind() == "identifier" => n,
                    _ => continue,
                };
                let var_name = get_node_text(&name_node, source).to_string();
                let line = node.start_position().row as u32 + 1;
                let scope = enclosing_ts_function_scope(&node, source);

                // Check value field first (new expression, as expression, literals)
                if let Some(value) = node.child_by_field_name("value") {
                    match value.kind() {
                        "new_expression" => {
                            // const x = new Foo(...)
                            if let Some(ctor) = value.child_by_field_name("constructor") {
                                let type_name = get_node_text(&ctor, source).to_string();
                                if !ts_builtin_types.contains(&type_name.as_str()) {
                                    var_types.push(VarType::new_with_scope(
                                        var_name.clone(),
                                        type_name,
                                        "assignment",
                                        line,
                                        scope.clone(),
                                    ));
                                }
                            }
                        }
                        "as_expression" => {
                            // const x = expr as Type
                            let child_count = value.named_child_count();
                            if child_count >= 2 {
                                if let Some(type_node) = value.named_child(child_count - 1) {
                                    let type_name = match type_node.kind() {
                                        "type_identifier" => {
                                            Some(get_node_text(&type_node, source).to_string())
                                        }
                                        "generic_type" => type_node
                                            .child_by_field_name("name")
                                            .map(|n| get_node_text(&n, source).to_string()),
                                        _ => None,
                                    };
                                    if let Some(tn) = type_name {
                                        if !ts_builtin_types.contains(&tn.as_str()) {
                                            var_types.push(VarType::new_with_scope(
                                                var_name.clone(),
                                                tn,
                                                "assertion",
                                                line,
                                                scope.clone(),
                                            ));
                                        }
                                    }
                                }
                            }
                        }
                        // Literal types
                        "string" | "template_string" => {
                            var_types.push(VarType::new_with_scope(
                                var_name.clone(),
                                "string".to_string(),
                                "literal",
                                line,
                                scope.clone(),
                            ));
                        }
                        "number" => {
                            var_types.push(VarType::new_with_scope(
                                var_name.clone(),
                                "number".to_string(),
                                "literal",
                                line,
                                scope.clone(),
                            ));
                        }
                        "true" | "false" => {
                            var_types.push(VarType::new_with_scope(
                                var_name.clone(),
                                "boolean".to_string(),
                                "literal",
                                line,
                                scope.clone(),
                            ));
                        }
                        "array" => {
                            var_types.push(VarType::new_with_scope(
                                var_name.clone(),
                                "Array".to_string(),
                                "literal",
                                line,
                                scope.clone(),
                            ));
                        }
                        "object" => {
                            var_types.push(VarType::new_with_scope(
                                var_name.clone(),
                                "Object".to_string(),
                                "literal",
                                line,
                                scope.clone(),
                            ));
                        }
                        "regex" => {
                            var_types.push(VarType::new_with_scope(
                                var_name.clone(),
                                "RegExp".to_string(),
                                "literal",
                                line,
                                scope.clone(),
                            ));
                        }
                        "null" => {
                            var_types.push(VarType::new_with_scope(
                                var_name.clone(),
                                "null".to_string(),
                                "literal",
                                line,
                                scope.clone(),
                            ));
                        }
                        // FEATURE-1 d.5 (Part A): const x = make() where make(): T has
                        // a declared return type. Only when there is no explicit type
                        // annotation (which would be High-confidence and win).
                        "call_expression" => {
                            if node.child_by_field_name("type").is_none() {
                                if let Some(callee) = value.child_by_field_name("function") {
                                    if callee.kind() == "identifier" {
                                        let callee_name = get_node_text(&callee, source);
                                        if let Some(rt) = lookup_fn_return(&fn_return, callee_name) {
                                            var_types.push(VarType::new_with_scope(
                                                var_name.clone(),
                                                rt.to_string(),
                                                "return",
                                                line,
                                                scope.clone(),
                                            ));
                                        }
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }

                // Check type annotation: let x: Type or const x: Type = new Foo()
                // Type annotation takes priority for the type mapping
                if let Some(type_ann) = node.child_by_field_name("type") {
                    // type_ann is the type_annotation node, its first named child is the type
                    if let Some(type_node) = type_ann.named_child(0) {
                        let type_name = match type_node.kind() {
                            "type_identifier" => {
                                Some(get_node_text(&type_node, source).to_string())
                            }
                            "generic_type" => type_node
                                .child_by_field_name("name")
                                .map(|n| get_node_text(&n, source).to_string()),
                            _ => None,
                        };
                        if let Some(tn) = type_name {
                            if !ts_builtin_types.contains(&tn.as_str()) {
                                var_types.push(VarType::new_with_scope(
                                    var_name,
                                    tn,
                                    "annotation",
                                    line,
                                    scope,
                                ));
                            }
                        }
                    }
                }
            }

            // Pattern 2: function f(x: Foo) -- typed parameters
            "required_parameter" | "optional_parameter" => {
                let name_node = match node.child_by_field_name("pattern") {
                    Some(n) if n.kind() == "identifier" => n,
                    _ => {
                        // Fallback: try first named child
                        match node.named_child(0) {
                            Some(n) if n.kind() == "identifier" => n,
                            _ => continue,
                        }
                    }
                };

                let type_ann = match node.child_by_field_name("type") {
                    Some(n) => n,
                    None => continue,
                };

                let var_name = get_node_text(&name_node, source).to_string();
                let line = node.start_position().row as u32 + 1;
                let scope = enclosing_ts_function_scope(&node, source);

                if let Some(type_node) = type_ann.named_child(0) {
                    let type_name = match type_node.kind() {
                        "type_identifier" => Some(get_node_text(&type_node, source).to_string()),
                        "generic_type" => type_node
                            .child_by_field_name("name")
                            .map(|n| get_node_text(&n, source).to_string()),
                        _ => None,
                    };
                    if let Some(tn) = type_name {
                        if !ts_builtin_types.contains(&tn.as_str()) {
                            var_types.push(VarType::new_with_scope(
                                var_name,
                                tn,
                                "parameter",
                                line,
                                scope,
                            ));
                        }
                    }
                }
            }

            _ => {}
        }
    }

    var_types
}

// =============================================================================
// Java VarType extraction
// =============================================================================

/// Determine the enclosing function scope for a Java AST node.
pub(crate) fn enclosing_java_function_scope(
    node: &tree_sitter::Node,
    source: &[u8],
) -> Option<String> {
    let mut current = node.parent();
    while let Some(parent) = current {
        match parent.kind() {
            "method_declaration" | "constructor_declaration" => {
                let method_name = parent
                    .child_by_field_name("name")
                    .map(|n| get_node_text(&n, source).to_string());
                if let Some(name) = method_name {
                    // Try to get class name: method_declaration > class_body > class_declaration
                    if let Some(class_body) = parent.parent() {
                        if class_body.kind() == "class_body" {
                            if let Some(class_decl) = class_body.parent() {
                                if class_decl.kind() == "class_declaration" {
                                    if let Some(class_name_node) =
                                        class_decl.child_by_field_name("name")
                                    {
                                        let class_name = get_node_text(&class_name_node, source);
                                        return Some(format!("{}.{}", class_name, name));
                                    }
                                }
                            }
                        }
                    }
                    return Some(name);
                }
            }
            _ => {}
        }
        current = parent.parent();
    }
    None
}

/// FEATURE-1 d.5 (Part A): normalise a Java type node to a bare nominal name
/// (`ArrayList<String>` -> `ArrayList`).
fn java_type_name(type_node: &tree_sitter::Node, source: &[u8]) -> String {
    if type_node.kind() == "generic_type" {
        type_node
            .named_child(0)
            .map(|n| get_node_text(&n, source).to_string())
            .unwrap_or_else(|| get_node_text(type_node, source).to_string())
    } else {
        get_node_text(type_node, source).to_string()
    }
}

/// FEATURE-1 d.5 (Part A): build the per-file `method simple name -> declared
/// return type` map for Java (`T method(..)`).
fn java_fn_return_map(
    root: tree_sitter::Node,
    source: &[u8],
    builtins: &[&str],
) -> HashMap<String, Option<String>> {
    let mut map: HashMap<String, Option<String>> = HashMap::new();
    for node in walk_tree(root) {
        if node.kind() != "method_declaration" {
            continue;
        }
        let name = match node.child_by_field_name("name") {
            Some(n) => get_node_text(&n, source).to_string(),
            None => continue,
        };
        let type_node = match node.child_by_field_name("type") {
            Some(t) => t,
            None => continue,
        };
        let rt = java_type_name(&type_node, source);
        if !rt.is_empty() && !builtins.contains(&rt.as_str()) {
            record_fn_return(&mut map, name, rt);
        }
    }
    map
}

/// Extract VarType entries from a Java source tree.
pub(crate) fn extract_java_var_types(tree: &tree_sitter::Tree, source: &[u8]) -> Vec<VarType> {
    let mut var_types = Vec::new();
    let root = tree.root_node();

    // Java builtin/primitive types that should not match project classes
    let java_builtin_types = [
        "String",
        "int",
        "Integer",
        "double",
        "Double",
        "float",
        "Float",
        "long",
        "Long",
        "boolean",
        "Boolean",
        "byte",
        "Byte",
        "short",
        "Short",
        "char",
        "Character",
        "void",
        "Object",
        "Number",
        "Comparable",
        "Serializable",
        "Cloneable",
        "Iterable",
        "AutoCloseable",
        "Throwable",
        "Exception",
        "RuntimeException",
        "Error",
        "var",
    ];

    // FEATURE-1 d.5 (Part A): declared return types for same-file methods.
    let fn_return = java_fn_return_map(root, source, &java_builtin_types);

    for node in walk_tree(root) {
        match node.kind() {
            // Pattern 1: Type var = new Type() or Type var = expr or Type var;
            "local_variable_declaration" => {
                // Get the type from the "type" field
                let type_node = match node.child_by_field_name("type") {
                    Some(n) => n,
                    None => continue,
                };

                let raw_type_text = get_node_text(&type_node, source).to_string();

                // Extract base type name: for generic_type like "ArrayList<String>", get "ArrayList"
                let type_name = if type_node.kind() == "generic_type" {
                    // First named child of generic_type is the base type_identifier
                    type_node
                        .named_child(0)
                        .map(|n| get_node_text(&n, source).to_string())
                        .unwrap_or(raw_type_text.clone())
                } else {
                    raw_type_text.clone()
                };

                // Get declarator(s) -- there can be multiple: int x = 1, y = 2;
                for i in 0..node.named_child_count() {
                    let child = match node.named_child(i) {
                        Some(c) if c.kind() == "variable_declarator" => c,
                        _ => continue,
                    };

                    let name_node = match child.child_by_field_name("name") {
                        Some(n) if n.kind() == "identifier" => n,
                        _ => continue,
                    };
                    let var_name = get_node_text(&name_node, source).to_string();
                    let line = child.start_position().row as u32 + 1;
                    let scope = enclosing_java_function_scope(&node, source);

                    // Check if type is "var" -- infer from RHS
                    if type_name == "var" {
                        if let Some(value) = child.child_by_field_name("value") {
                            if value.kind() == "object_creation_expression" {
                                // var x = new Dog() -- extract type from the constructor
                                if let Some(ctor_type) = value.child_by_field_name("type") {
                                    let ctor_type_name = if ctor_type.kind() == "generic_type" {
                                        ctor_type
                                            .named_child(0)
                                            .map(|n| get_node_text(&n, source).to_string())
                                            .unwrap_or_else(|| {
                                                get_node_text(&ctor_type, source).to_string()
                                            })
                                    } else {
                                        get_node_text(&ctor_type, source).to_string()
                                    };
                                    if !java_builtin_types.contains(&ctor_type_name.as_str()) {
                                        var_types.push(VarType::new_with_scope(
                                            var_name,
                                            ctor_type_name,
                                            "constructor",
                                            line,
                                            scope,
                                        ));
                                    }
                                }
                            } else if value.kind() == "method_invocation" {
                                // FEATURE-1 d.5 (Part A): var x = make() where make() has
                                // a declared return type T.
                                if let Some(callee) = value.child_by_field_name("name") {
                                    let callee_name = get_node_text(&callee, source);
                                    if let Some(rt) = lookup_fn_return(&fn_return, callee_name) {
                                        var_types.push(VarType::new_with_scope(
                                            var_name,
                                            rt.to_string(),
                                            "return",
                                            line,
                                            scope,
                                        ));
                                    }
                                }
                            }
                        }
                        continue;
                    }

                    // Skip builtin types
                    if java_builtin_types.contains(&type_name.as_str()) {
                        continue;
                    }

                    // Check if the value is a constructor call: new Type(...)
                    let source_kind = if let Some(value) = child.child_by_field_name("value") {
                        if value.kind() == "object_creation_expression" {
                            "constructor"
                        } else {
                            "annotation"
                        }
                    } else {
                        // No initializer: Type var;
                        "annotation"
                    };

                    var_types.push(VarType::new_with_scope(
                        var_name,
                        type_name.clone(),
                        source_kind,
                        line,
                        scope,
                    ));
                }
            }

            // Pattern 2: field_declaration -- same structure as local_variable_declaration
            "field_declaration" => {
                let type_node = match node.child_by_field_name("type") {
                    Some(n) => n,
                    None => continue,
                };

                let raw_type_text = get_node_text(&type_node, source).to_string();

                let type_name = if type_node.kind() == "generic_type" {
                    type_node
                        .named_child(0)
                        .map(|n| get_node_text(&n, source).to_string())
                        .unwrap_or(raw_type_text.clone())
                } else {
                    raw_type_text.clone()
                };

                if java_builtin_types.contains(&type_name.as_str()) {
                    continue;
                }

                for i in 0..node.named_child_count() {
                    let child = match node.named_child(i) {
                        Some(c) if c.kind() == "variable_declarator" => c,
                        _ => continue,
                    };

                    let name_node = match child.child_by_field_name("name") {
                        Some(n) if n.kind() == "identifier" => n,
                        _ => continue,
                    };
                    let var_name = get_node_text(&name_node, source).to_string();
                    let line = child.start_position().row as u32 + 1;

                    // Fields are at class scope, not method scope
                    // Walk up to find class name
                    let scope = {
                        let mut s = None;
                        let mut cur = node.parent();
                        while let Some(p) = cur {
                            if p.kind() == "class_body" {
                                if let Some(class_decl) = p.parent() {
                                    if class_decl.kind() == "class_declaration" {
                                        if let Some(cn) = class_decl.child_by_field_name("name") {
                                            s = Some(get_node_text(&cn, source).to_string());
                                        }
                                    }
                                }
                                break;
                            }
                            cur = p.parent();
                        }
                        s
                    };

                    let source_kind = if let Some(value) = child.child_by_field_name("value") {
                        if value.kind() == "object_creation_expression" {
                            "constructor"
                        } else {
                            "annotation"
                        }
                    } else {
                        "annotation"
                    };

                    var_types.push(VarType::new_with_scope(
                        var_name,
                        type_name.clone(),
                        source_kind,
                        line,
                        scope,
                    ));
                }
            }

            // Pattern 3: formal_parameter -- method/constructor parameters
            "formal_parameter" => {
                let type_node = match node.child_by_field_name("type") {
                    Some(n) => n,
                    None => continue,
                };
                let name_node = match node.child_by_field_name("name") {
                    Some(n) if n.kind() == "identifier" => n,
                    _ => continue,
                };

                let raw_type_text = get_node_text(&type_node, source).to_string();
                let type_name = if type_node.kind() == "generic_type" {
                    type_node
                        .named_child(0)
                        .map(|n| get_node_text(&n, source).to_string())
                        .unwrap_or(raw_type_text.clone())
                } else {
                    raw_type_text.clone()
                };

                if java_builtin_types.contains(&type_name.as_str()) {
                    continue;
                }

                let var_name = get_node_text(&name_node, source).to_string();
                let line = node.start_position().row as u32 + 1;
                let scope = enclosing_java_function_scope(&node, source);

                var_types.push(VarType::new_with_scope(
                    var_name,
                    type_name,
                    "parameter",
                    line,
                    scope,
                ));
            }

            // Pattern 4: enhanced_for_statement -- for (Type var : collection)
            "enhanced_for_statement" => {
                let type_node = match node.child_by_field_name("type") {
                    Some(n) => n,
                    None => continue,
                };
                let name_node = match node.child_by_field_name("name") {
                    Some(n) if n.kind() == "identifier" => n,
                    _ => continue,
                };

                let raw_type_text = get_node_text(&type_node, source).to_string();
                let type_name = if type_node.kind() == "generic_type" {
                    type_node
                        .named_child(0)
                        .map(|n| get_node_text(&n, source).to_string())
                        .unwrap_or(raw_type_text.clone())
                } else {
                    raw_type_text.clone()
                };

                if java_builtin_types.contains(&type_name.as_str()) {
                    continue;
                }

                let var_name = get_node_text(&name_node, source).to_string();
                let line = node.start_position().row as u32 + 1;
                let scope = enclosing_java_function_scope(&node, source);

                var_types.push(VarType::new_with_scope(
                    var_name,
                    type_name,
                    "annotation",
                    line,
                    scope,
                ));
            }

            // Pattern 5: cast_expression -- (Type) expr
            "cast_expression" => {
                let type_node = match node.child_by_field_name("type") {
                    Some(n) => n,
                    None => continue,
                };

                // Only useful if the cast result is assigned -- check parent
                let parent = match node.parent() {
                    Some(p) => p,
                    None => continue,
                };

                // Only track if parent is a variable_declarator (assignment context)
                if parent.kind() != "variable_declarator" {
                    continue;
                }

                let name_node = match parent.child_by_field_name("name") {
                    Some(n) if n.kind() == "identifier" => n,
                    _ => continue,
                };

                let raw_type_text = get_node_text(&type_node, source).to_string();
                let type_name = if type_node.kind() == "generic_type" {
                    type_node
                        .named_child(0)
                        .map(|n| get_node_text(&n, source).to_string())
                        .unwrap_or(raw_type_text.clone())
                } else {
                    raw_type_text.clone()
                };

                if java_builtin_types.contains(&type_name.as_str()) {
                    continue;
                }

                let var_name = get_node_text(&name_node, source).to_string();
                let line = node.start_position().row as u32 + 1;
                let scope = enclosing_java_function_scope(&node, source);

                var_types.push(VarType::new_with_scope(
                    var_name,
                    type_name,
                    "annotation",
                    line,
                    scope,
                ));
            }

            _ => {}
        }
    }

    var_types
}

// =============================================================================
// Rust VarType extraction
// =============================================================================

/// Determine the enclosing function scope for a Rust AST node.
pub(crate) fn enclosing_rust_function_scope(
    node: &tree_sitter::Node,
    source: &[u8],
) -> Option<String> {
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "function_item" {
            let fn_name = parent
                .child_by_field_name("name")
                .map(|n| get_node_text(&n, source).to_string());
            if let Some(name) = fn_name {
                // Check if inside an impl block: function_item -> declaration_list -> impl_item
                if let Some(decl_list) = parent.parent() {
                    if decl_list.kind() == "declaration_list" {
                        if let Some(impl_item) = decl_list.parent() {
                            if impl_item.kind() == "impl_item" {
                                // Get the type being implemented
                                if let Some(type_node) = impl_item.child_by_field_name("type") {
                                    let type_name = get_node_text(&type_node, source);
                                    return Some(format!("{}.{}", type_name, name));
                                }
                            }
                        }
                    }
                }
                return Some(name);
            }
        }
        current = parent.parent();
    }
    None
}

/// Extract VarType entries from a Rust source tree.
/// FEATURE-1 d.5 (Part A): build the per-file `fn simple name -> declared return
/// type` map for Rust (`fn f(..) -> T`).
fn rust_fn_return_map(
    root: tree_sitter::Node,
    source: &[u8],
    builtins: &[&str],
) -> HashMap<String, Option<String>> {
    let mut map: HashMap<String, Option<String>> = HashMap::new();
    for node in walk_tree(root) {
        if node.kind() != "function_item" {
            continue;
        }
        let name = match node.child_by_field_name("name") {
            Some(n) => get_node_text(&n, source).to_string(),
            None => continue,
        };
        let ret = match node.child_by_field_name("return_type") {
            Some(r) => r,
            None => continue,
        };
        if let Some(rt) = extract_rust_type_name(&ret, source) {
            if !rt.is_empty() && !builtins.contains(&rt.as_str()) {
                record_fn_return(&mut map, name, rt);
            }
        }
    }
    map
}

pub(crate) fn extract_rust_var_types(tree: &tree_sitter::Tree, source: &[u8]) -> Vec<VarType> {
    let mut var_types = Vec::new();
    let root = tree.root_node();

    let rust_builtin_types = [
        "i8", "i16", "i32", "i64", "i128", "isize", "u8", "u16", "u32", "u64", "u128", "usize",
        "f32", "f64", "bool", "char", "str", "String", "Vec", "HashMap", "HashSet", "BTreeMap",
        "BTreeSet", "Option", "Result", "Box", "Rc", "Arc", "Cow", "Cell", "RefCell", "Mutex",
        "RwLock", "Pin", "Waker", "Context",
    ];

    // FEATURE-1 d.5 (Part A): declared return types for same-file fns.
    let fn_return = rust_fn_return_map(root, source, &rust_builtin_types);

    // Track vars already assigned via constructor (prefer constructor over annotation)
    let mut constructor_vars: HashSet<(String, Option<String>)> = HashSet::new();

    for node in walk_tree(root) {
        match node.kind() {
            "let_declaration" => {
                let line = node.start_position().row as u32 + 1;
                let scope = enclosing_rust_function_scope(&node, source);

                let pattern_node = match node.child_by_field_name("pattern") {
                    Some(n) => n,
                    None => continue,
                };

                // Check RHS value first (for constructor detection)
                if let Some(value_node) = node.child_by_field_name("value") {
                    match value_node.kind() {
                        // Pattern 1: let dog = Dog::new(...) -- scoped identifier constructor
                        "call_expression" => {
                            if let Some(func_node) = value_node.child_by_field_name("function") {
                                if func_node.kind() == "scoped_identifier" {
                                    if let Some(path_node) = func_node.child_by_field_name("path") {
                                        let type_name =
                                            get_node_text(&path_node, source).to_string();

                                        if pattern_node.kind() == "identifier" {
                                            let var_name =
                                                get_node_text(&pattern_node, source).to_string();
                                            if !rust_builtin_types.contains(&type_name.as_str())
                                                && !var_name.starts_with('_')
                                            {
                                                constructor_vars
                                                    .insert((var_name.clone(), scope.clone()));
                                                var_types.push(VarType::new_with_scope(
                                                    var_name,
                                                    type_name,
                                                    "constructor",
                                                    line,
                                                    scope,
                                                ));
                                                continue;
                                            }
                                        }
                                    }
                                } else if func_node.kind() == "identifier"
                                    && pattern_node.kind() == "identifier"
                                    && node.child_by_field_name("type").is_none()
                                {
                                    // FEATURE-1 d.5 (Part A): let x = make() where the free
                                    // function `make` has a declared `-> T` return type.
                                    let callee = get_node_text(&func_node, source);
                                    let var_name =
                                        get_node_text(&pattern_node, source).to_string();
                                    if !var_name.starts_with('_') {
                                        if let Some(rt) = lookup_fn_return(&fn_return, callee) {
                                            var_types.push(VarType::new_with_scope(
                                                var_name,
                                                rt.to_string(),
                                                "return",
                                                line,
                                                scope,
                                            ));
                                            continue;
                                        }
                                    }
                                }
                            }
                        }
                        // Pattern 2: let animal = Animal { name: ... } -- struct expression
                        "struct_expression" => {
                            if let Some(name_node) = value_node.child_by_field_name("name") {
                                let type_name = get_node_text(&name_node, source).to_string();

                                if pattern_node.kind() == "identifier" {
                                    let var_name = get_node_text(&pattern_node, source).to_string();
                                    if !rust_builtin_types.contains(&type_name.as_str())
                                        && !var_name.starts_with('_')
                                    {
                                        constructor_vars.insert((var_name.clone(), scope.clone()));
                                        var_types.push(VarType::new_with_scope(
                                            var_name,
                                            type_name,
                                            "constructor",
                                            line,
                                            scope,
                                        ));
                                        continue;
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }

                // Pattern 3: let a: Animal = ... -- explicit type annotation
                if let Some(type_node) = node.child_by_field_name("type") {
                    if pattern_node.kind() == "identifier" {
                        let var_name = get_node_text(&pattern_node, source).to_string();
                        if var_name.starts_with('_') {
                            continue;
                        }

                        // Skip if already found via constructor
                        if constructor_vars.contains(&(var_name.clone(), scope.clone())) {
                            continue;
                        }

                        let type_name = extract_rust_type_name(&type_node, source);
                        if let Some(tn) = type_name {
                            if !rust_builtin_types.contains(&tn.as_str()) {
                                var_types.push(VarType::new_with_scope(
                                    var_name,
                                    tn,
                                    "annotation",
                                    line,
                                    scope,
                                ));
                            }
                        }
                    }
                }
            }

            // Pattern 4: fn process(animal: &Animal) -- function parameters
            "parameter" => {
                let line = node.start_position().row as u32 + 1;
                let scope = enclosing_rust_function_scope(&node, source);

                let pattern_node = match node.child_by_field_name("pattern") {
                    Some(n) if n.kind() == "identifier" => n,
                    _ => continue,
                };
                let var_name = get_node_text(&pattern_node, source).to_string();
                if var_name.starts_with('_') {
                    continue;
                }

                let type_child = match node.child_by_field_name("type") {
                    Some(n) => n,
                    None => continue,
                };

                let type_name = extract_rust_type_name(&type_child, source);
                if let Some(tn) = type_name {
                    if !rust_builtin_types.contains(&tn.as_str()) {
                        var_types.push(VarType::new_with_scope(
                            var_name,
                            tn,
                            "parameter",
                            line,
                            scope,
                        ));
                    }
                }
            }

            _ => {}
        }
    }

    var_types
}

/// Extract the base type name from a Rust type AST node.
pub(crate) fn extract_rust_type_name(
    type_node: &tree_sitter::Node,
    source: &[u8],
) -> Option<String> {
    match type_node.kind() {
        "type_identifier" => Some(get_node_text(type_node, source).to_string()),
        "reference_type" => {
            for i in 0..type_node.named_child_count() {
                if let Some(child) = type_node.named_child(i) {
                    if let Some(result) = extract_rust_type_name(&child, source) {
                        return Some(result);
                    }
                }
            }
            None
        }
        "generic_type" => type_node
            .named_child(0)
            .and_then(|n| extract_rust_type_name(&n, source)),
        "scoped_type_identifier" => {
            if let Some(name_node) = type_node.child_by_field_name("name") {
                Some(get_node_text(&name_node, source).to_string())
            } else {
                Some(get_node_text(type_node, source).to_string())
            }
        }
        _ => None,
    }
}

// =============================================================================
// Kotlin VarType extraction
// =============================================================================

/// Determine the enclosing function scope for a Kotlin AST node.
pub(crate) fn enclosing_kotlin_function_scope(
    node: &tree_sitter::Node,
    source: &[u8],
) -> Option<String> {
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "function_declaration" {
            let fn_name = parent
                .child_by_field_name("name")
                .map(|n| get_node_text(&n, source).to_string());
            if let Some(name) = fn_name {
                if let Some(class_body) = parent.parent() {
                    if class_body.kind() == "class_body" {
                        if let Some(class_decl) = class_body.parent() {
                            if class_decl.kind() == "class_declaration" {
                                if let Some(class_name_node) =
                                    class_decl.child_by_field_name("name")
                                {
                                    let class_name = get_node_text(&class_name_node, source);
                                    return Some(format!("{}.{}", class_name, name));
                                }
                            }
                        }
                    }
                }
                return Some(name);
            }
        }
        current = parent.parent();
    }
    None
}

/// Extract the base type name from a Kotlin type AST node.
pub(crate) fn extract_kotlin_type_name(
    type_node: &tree_sitter::Node,
    source: &[u8],
) -> Option<String> {
    match type_node.kind() {
        "user_type" => {
            for i in 0..type_node.child_count() {
                if let Some(child) = type_node.child(i) {
                    if child.kind() == "identifier"
                        || child.kind() == "simple_identifier"
                        || child.kind() == "type_identifier"
                    {
                        return Some(get_node_text(&child, source).to_string());
                    }
                    if child.kind() == "simple_user_type" {
                        for j in 0..child.child_count() {
                            if let Some(inner) = child.child(j) {
                                if inner.kind() == "identifier"
                                    || inner.kind() == "simple_identifier"
                                    || inner.kind() == "type_identifier"
                                {
                                    return Some(get_node_text(&inner, source).to_string());
                                }
                            }
                        }
                        let text = get_node_text(&child, source).to_string();
                        if let Some(idx) = text.find('<') {
                            return Some(text[..idx].to_string());
                        }
                        return Some(text);
                    }
                }
            }
            let text = get_node_text(type_node, source).to_string();
            if let Some(idx) = text.find('<') {
                Some(text[..idx].to_string())
            } else {
                Some(text)
            }
        }
        "nullable_type" => {
            for i in 0..type_node.named_child_count() {
                if let Some(child) = type_node.named_child(i) {
                    if let Some(result) = extract_kotlin_type_name(&child, source) {
                        return Some(result);
                    }
                }
            }
            None
        }
        "type_reference" => {
            for i in 0..type_node.named_child_count() {
                if let Some(child) = type_node.named_child(i) {
                    if let Some(result) = extract_kotlin_type_name(&child, source) {
                        return Some(result);
                    }
                }
            }
            None
        }
        "identifier" | "simple_identifier" | "type_identifier" => {
            Some(get_node_text(type_node, source).to_string())
        }
        _ => {
            for i in 0..type_node.named_child_count() {
                if let Some(child) = type_node.named_child(i) {
                    if let Some(result) = extract_kotlin_type_name(&child, source) {
                        return Some(result);
                    }
                }
            }
            None
        }
    }
}

/// FEATURE-1 d.5 (Part A): build the per-file `fun simple name -> declared return
/// type` map for Kotlin (`fun f(): T`). The return type is the first `user_type`/
/// `nullable_type`/`type_reference` child appearing AFTER the value parameters.
fn kotlin_fn_return_map(
    root: tree_sitter::Node,
    source: &[u8],
    builtins: &[&str],
) -> HashMap<String, Option<String>> {
    let mut map: HashMap<String, Option<String>> = HashMap::new();
    for node in walk_tree(root) {
        if node.kind() != "function_declaration" {
            continue;
        }
        let mut name: Option<String> = None;
        let mut seen_params = false;
        let mut rtype: Option<String> = None;
        for i in 0..node.child_count() {
            let child = match node.child(i) {
                Some(c) => c,
                None => continue,
            };
            match child.kind() {
                "simple_identifier" | "identifier" if name.is_none() => {
                    name = Some(get_node_text(&child, source).to_string());
                }
                "function_value_parameters" => seen_params = true,
                "user_type" | "nullable_type" | "type_reference" if seen_params => {
                    if rtype.is_none() {
                        rtype = extract_kotlin_type_name(&child, source);
                    }
                }
                _ => {}
            }
        }
        if let (Some(n), Some(rt)) = (name, rtype) {
            if !rt.is_empty() && !builtins.contains(&rt.as_str()) {
                record_fn_return(&mut map, n, rt);
            }
        }
    }
    map
}

/// Extract VarType entries from a Kotlin source tree.
pub(crate) fn extract_kotlin_var_types(tree: &tree_sitter::Tree, source: &[u8]) -> Vec<VarType> {
    let mut var_types = Vec::new();
    let root = tree.root_node();

    let kotlin_builtin_types = [
        "String",
        "Int",
        "Long",
        "Double",
        "Float",
        "Boolean",
        "Byte",
        "Short",
        "Char",
        "Unit",
        "Nothing",
        "Any",
        "Number",
        "Comparable",
        "List",
        "Map",
        "Set",
        "MutableList",
        "MutableMap",
        "MutableSet",
        "Array",
        "IntArray",
        "LongArray",
        "DoubleArray",
        "FloatArray",
        "BooleanArray",
        "ByteArray",
        "ShortArray",
        "CharArray",
        "Pair",
        "Triple",
        "Sequence",
        "Iterable",
        "Exception",
        "RuntimeException",
        "Throwable",
        "Enum",
        "Annotation",
        "HashMap",
        "HashSet",
        "ArrayList",
        "LinkedList",
        "LinkedHashMap",
        "LinkedHashSet",
        "Regex",
        "StringBuilder",
        "Lazy",
    ];

    // FEATURE-1 d.5 (Part A): declared return types for same-file funs.
    let fn_return = kotlin_fn_return_map(root, source, &kotlin_builtin_types);

    for node in walk_tree(root) {
        match node.kind() {
            "property_declaration" => {
                let line = node.start_position().row as u32 + 1;
                let scope = enclosing_kotlin_function_scope(&node, source);

                let mut var_name: Option<String> = None;
                let mut type_name: Option<String> = None;
                let mut has_constructor_rhs = false;
                let mut constructor_type: Option<String> = None;
                let mut return_type_rhs: Option<String> = None;

                for i in 0..node.child_count() {
                    let child = match node.child(i) {
                        Some(c) => c,
                        None => continue,
                    };

                    match child.kind() {
                        "variable_declaration" => {
                            for j in 0..child.child_count() {
                                if let Some(inner) = child.child(j) {
                                    match inner.kind() {
                                        "identifier" | "simple_identifier" => {
                                            var_name =
                                                Some(get_node_text(&inner, source).to_string());
                                        }
                                        "user_type" | "nullable_type" | "type_reference" => {
                                            type_name = extract_kotlin_type_name(&inner, source);
                                        }
                                        _ => {
                                            if type_name.is_none() {
                                                if let Some(tn) =
                                                    extract_kotlin_type_name(&inner, source)
                                                {
                                                    if tn
                                                        .chars()
                                                        .next()
                                                        .is_some_and(|c| c.is_uppercase())
                                                    {
                                                        type_name = Some(tn);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        "identifier" | "simple_identifier" if var_name.is_none() => {
                            var_name = Some(get_node_text(&child, source).to_string());
                        }
                        "call_expression" => {
                            if let Some(func_child) = child.child(0) {
                                let call_text = get_node_text(&func_child, source).to_string();
                                // Simple callee name (last component of `Mod.make`).
                                let call_name =
                                    call_text.rsplit('.').next().unwrap_or(&call_text).to_string();
                                if call_name.chars().next().is_some_and(|c| c.is_uppercase()) {
                                    has_constructor_rhs = true;
                                    constructor_type = Some(call_name);
                                } else if let Some(rt) = lookup_fn_return(&fn_return, &call_name) {
                                    // FEATURE-1 d.5 (Part A): val x = make() where make(): T.
                                    return_type_rhs = Some(rt.to_string());
                                }
                            }
                        }
                        _ => {}
                    }
                }

                let var_name = match var_name {
                    Some(n) if !n.is_empty() => n,
                    _ => continue,
                };

                if let Some(ref tn) = type_name {
                    if !kotlin_builtin_types.contains(&tn.as_str()) {
                        var_types.push(VarType::new_with_scope(
                            var_name.clone(),
                            tn.clone(),
                            "annotation",
                            line,
                            scope.clone(),
                        ));
                        continue;
                    }
                }

                if has_constructor_rhs {
                    if let Some(ref ct) = constructor_type {
                        if !kotlin_builtin_types.contains(&ct.as_str()) {
                            var_types.push(VarType::new_with_scope(
                                var_name,
                                ct.clone(),
                                "assignment",
                                line,
                                scope,
                            ));
                        }
                    }
                } else if let Some(rt) = return_type_rhs {
                    var_types.push(VarType::new_with_scope(
                        var_name,
                        rt,
                        "return",
                        line,
                        scope,
                    ));
                }
            }

            "parameter" => {
                let line = node.start_position().row as u32 + 1;
                let scope = enclosing_kotlin_function_scope(&node, source);

                let mut param_name: Option<String> = None;
                let mut param_type: Option<String> = None;

                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        match child.kind() {
                            "identifier" | "simple_identifier" if param_name.is_none() => {
                                param_name = Some(get_node_text(&child, source).to_string());
                            }
                            "user_type" | "nullable_type" | "type_reference" => {
                                param_type = extract_kotlin_type_name(&child, source);
                            }
                            _ => {
                                if param_type.is_none() {
                                    if let Some(tn) = extract_kotlin_type_name(&child, source) {
                                        if tn.chars().next().is_some_and(|c| c.is_uppercase()) {
                                            param_type = Some(tn);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                if let (Some(name), Some(type_name)) = (param_name, param_type) {
                    if !kotlin_builtin_types.contains(&type_name.as_str()) {
                        var_types.push(VarType::new_with_scope(
                            name,
                            type_name,
                            "parameter",
                            line,
                            scope,
                        ));
                    }
                }
            }

            "class_parameter" => {
                let line = node.start_position().row as u32 + 1;

                let scope = {
                    let mut s = None;
                    let mut cur = node.parent();
                    while let Some(p) = cur {
                        if p.kind() == "class_parameters" {
                            if let Some(ctor) = p.parent() {
                                if ctor.kind() == "primary_constructor" {
                                    if let Some(class_decl) = ctor.parent() {
                                        if class_decl.kind() == "class_declaration" {
                                            if let Some(cn) = class_decl.child_by_field_name("name")
                                            {
                                                s = Some(get_node_text(&cn, source).to_string());
                                            }
                                        }
                                    }
                                }
                                if ctor.kind() == "class_declaration" {
                                    if let Some(cn) = ctor.child_by_field_name("name") {
                                        s = Some(get_node_text(&cn, source).to_string());
                                    }
                                }
                            }
                            break;
                        }
                        cur = p.parent();
                    }
                    s
                };

                let mut param_name: Option<String> = None;
                let mut param_type: Option<String> = None;

                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        match child.kind() {
                            "identifier" | "simple_identifier" if param_name.is_none() => {
                                param_name = Some(get_node_text(&child, source).to_string());
                            }
                            "user_type" | "nullable_type" | "type_reference" => {
                                param_type = extract_kotlin_type_name(&child, source);
                            }
                            "modifiers" | "val" | "var" => {}
                            _ => {
                                if param_type.is_none() {
                                    if let Some(tn) = extract_kotlin_type_name(&child, source) {
                                        if tn.chars().next().is_some_and(|c| c.is_uppercase()) {
                                            param_type = Some(tn);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                if let (Some(name), Some(type_name)) = (param_name, param_type) {
                    if !kotlin_builtin_types.contains(&type_name.as_str()) {
                        var_types.push(VarType::new_with_scope(
                            name,
                            type_name,
                            "parameter",
                            line,
                            scope,
                        ));
                    }
                }
            }

            _ => {}
        }
    }

    var_types
}

// =============================================================================
// PHP VarType extraction
// =============================================================================

/// Determine the enclosing function/method scope for a PHP AST node.
pub(crate) fn enclosing_php_function_scope(
    node: &tree_sitter::Node,
    source: &[u8],
) -> Option<String> {
    let mut cur = node.parent();
    while let Some(p) = cur {
        match p.kind() {
            "method_declaration" => {
                let method_name = p
                    .child_by_field_name("name")
                    .map(|n| get_node_text(&n, source).to_string());
                let mut class_name = None;
                let mut parent = p.parent();
                while let Some(pp) = parent {
                    if pp.kind() == "declaration_list" {
                        if let Some(class_decl) = pp.parent() {
                            if class_decl.kind() == "class_declaration" {
                                class_name = class_decl
                                    .child_by_field_name("name")
                                    .map(|n| get_node_text(&n, source).to_string());
                            }
                        }
                        break;
                    }
                    parent = pp.parent();
                }
                return match (class_name, method_name) {
                    (Some(cn), Some(mn)) => Some(format!("{}.{}", cn, mn)),
                    (None, Some(mn)) => Some(mn),
                    _ => None,
                };
            }
            "function_definition" => {
                return p
                    .child_by_field_name("name")
                    .map(|n| get_node_text(&n, source).to_string());
            }
            _ => {}
        }
        cur = p.parent();
    }
    None // top-level / module scope
}

/// Extract the base type name from a PHP type AST node.
pub(crate) fn extract_php_type_name(
    type_node: &tree_sitter::Node,
    source: &[u8],
) -> Option<String> {
    match type_node.kind() {
        "named_type" => {
            let text = get_node_text(type_node, source).to_string();
            let base = text.rsplit('\\').next().unwrap_or(&text);
            if base.is_empty() {
                None
            } else {
                Some(base.to_string())
            }
        }
        "optional_type" => {
            for i in 0..type_node.named_child_count() {
                if let Some(child) = type_node.named_child(i) {
                    if let Some(result) = extract_php_type_name(&child, source) {
                        return Some(result);
                    }
                }
            }
            None
        }
        "nullable_type" => {
            for i in 0..type_node.named_child_count() {
                if let Some(child) = type_node.named_child(i) {
                    if let Some(result) = extract_php_type_name(&child, source) {
                        return Some(result);
                    }
                }
            }
            None
        }
        "union_type" | "intersection_type" => None,
        _ => None,
    }
}

/// Extract VarType entries from a PHP source tree.
pub(crate) fn extract_php_var_types(tree: &tree_sitter::Tree, source: &[u8]) -> Vec<VarType> {
    let mut var_types = Vec::new();
    let root = tree.root_node();

    let php_builtin_types = [
        "string", "int", "float", "bool", "array", "object", "callable", "iterable", "mixed",
        "void", "null", "never", "false", "true", "self", "static", "parent", "resource",
    ];

    for node in walk_tree(root) {
        match node.kind() {
            // Pattern 1: $x = new Foo()
            "assignment_expression" => {
                let left = match node.child_by_field_name("left") {
                    Some(n) if n.kind() == "variable_name" => n,
                    _ => continue,
                };
                let right = match node.child_by_field_name("right") {
                    Some(n) if n.kind() == "object_creation_expression" => n,
                    _ => continue,
                };

                let var_text = get_node_text(&left, source).to_string();
                let var_name = var_text.trim_start_matches('$');
                if var_name.is_empty() {
                    continue;
                }

                let mut class_name: Option<String> = None;
                for i in 0..right.child_count() {
                    if let Some(child) = right.child(i) {
                        if child.kind() == "name" {
                            let raw = get_node_text(&child, source).to_string();
                            let base = raw.rsplit('\\').next().unwrap_or(&raw);
                            if !base.is_empty() {
                                class_name = Some(base.to_string());
                            }
                            break;
                        }
                        if child.kind() == "qualified_name" {
                            let raw = get_node_text(&child, source).to_string();
                            let base = raw.rsplit('\\').next().unwrap_or(&raw);
                            if !base.is_empty() {
                                class_name = Some(base.to_string());
                            }
                            break;
                        }
                    }
                }

                let type_name = match class_name {
                    Some(ref tn) if !php_builtin_types.contains(&tn.to_lowercase().as_str()) => {
                        tn.clone()
                    }
                    _ => continue,
                };

                let line = node.start_position().row as u32 + 1;
                let scope = enclosing_php_function_scope(&node, source);

                var_types.push(VarType::new_with_scope(
                    var_name.to_string(),
                    type_name,
                    "constructor",
                    line,
                    scope,
                ));
            }

            // Pattern 2: function f(Foo $x) {}
            "simple_parameter" => {
                let type_node = match node.child_by_field_name("type") {
                    Some(n) => n,
                    None => continue,
                };

                let type_name = match extract_php_type_name(&type_node, source) {
                    Some(tn) if !php_builtin_types.contains(&tn.to_lowercase().as_str()) => tn,
                    _ => continue,
                };

                let name_node = match node.child_by_field_name("name") {
                    Some(n) => n,
                    None => continue,
                };

                let var_text = get_node_text(&name_node, source).to_string();
                let var_name = var_text.trim_start_matches('$');
                if var_name.is_empty() {
                    continue;
                }

                let line = node.start_position().row as u32 + 1;
                let scope = enclosing_php_function_scope(&node, source);

                var_types.push(VarType::new_with_scope(
                    var_name.to_string(),
                    type_name,
                    "parameter",
                    line,
                    scope,
                ));
            }

            // Pattern 3: private Foo $prop;
            "property_declaration" => {
                let type_node = match node.child_by_field_name("type") {
                    Some(n) => n,
                    None => continue,
                };

                let type_name = match extract_php_type_name(&type_node, source) {
                    Some(tn) if !php_builtin_types.contains(&tn.to_lowercase().as_str()) => tn,
                    _ => continue,
                };

                let mut var_name: Option<String> = None;
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if child.kind() == "property_element" {
                            for j in 0..child.child_count() {
                                if let Some(inner) = child.child(j) {
                                    if inner.kind() == "variable_name" {
                                        let var_text = get_node_text(&inner, source).to_string();
                                        let name = var_text.trim_start_matches('$');
                                        if !name.is_empty() {
                                            var_name = Some(name.to_string());
                                        }
                                        break;
                                    }
                                }
                            }
                            break;
                        }
                    }
                }

                let var_name = match var_name {
                    Some(n) => n,
                    None => continue,
                };

                let line = node.start_position().row as u32 + 1;
                let scope = enclosing_php_function_scope(&node, source);

                var_types.push(VarType::new_with_scope(
                    var_name,
                    type_name,
                    "annotation",
                    line,
                    scope,
                ));
            }

            _ => {}
        }
    }

    var_types
}

// =============================================================================
// C# VarType extraction (FEATURE-1 d.5 Part A: declared-return propagation)
// =============================================================================
//
// C# has no var_types extractor before d.5. This one is intentionally scoped to
// the d.5 deliverable: it emits ONLY return-derived rows for `var x = Make();`
// where `Make()` has a declared (non-`void`, non-predefined) return type, so
// `x.Method()` resolves type-scoped. It never emits any other kind of row, so it
// can only FILL a previously-`None` receiver type (never-worse).

/// Determine the enclosing `Class.Method` (or bare method) scope for a C# node so
/// the emitted VarType scope matches the caller key produced by the call handler.
fn enclosing_csharp_function_scope(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    let mut cur = node.parent();
    while let Some(p) = cur {
        if p.kind() == "method_declaration" || p.kind() == "local_function_statement" {
            let method = p
                .child_by_field_name("name")
                .map(|n| get_node_text(&n, source).to_string())?;
            // Find the enclosing type declaration for qualification.
            let mut c2 = p.parent();
            while let Some(pp) = c2 {
                if matches!(
                    pp.kind(),
                    "class_declaration" | "struct_declaration" | "record_declaration"
                ) {
                    if let Some(cn) = pp.child_by_field_name("name") {
                        return Some(format!(
                            "{}.{}",
                            get_node_text(&cn, source),
                            method
                        ));
                    }
                }
                c2 = pp.parent();
            }
            return Some(method);
        }
        cur = p.parent();
    }
    None
}

/// FEATURE-1 d.5 (Part A): build the per-file `method simple name -> declared
/// return type` map for C# (`T Method(..)`, via the `returns` field).
fn csharp_fn_return_map(root: tree_sitter::Node, source: &[u8]) -> HashMap<String, Option<String>> {
    let mut map: HashMap<String, Option<String>> = HashMap::new();
    for node in walk_tree(root) {
        if node.kind() != "method_declaration" {
            continue;
        }
        let name = match node.child_by_field_name("name") {
            Some(n) => get_node_text(&n, source).to_string(),
            None => continue,
        };
        let returns = match node.child_by_field_name("returns") {
            Some(r) => r,
            None => continue,
        };
        // Only nominal identifier / generic_name returns denote a project type;
        // `predefined_type` (void/int/string/...) is skipped.
        let rt = match returns.kind() {
            "identifier" => Some(get_node_text(&returns, source).to_string()),
            "generic_name" => returns
                .child_by_field_name("name")
                .map(|n| get_node_text(&n, source).to_string())
                .or_else(|| {
                    let t = get_node_text(&returns, source).to_string();
                    t.split('<').next().map(|s| s.to_string())
                }),
            "qualified_name" => {
                let t = get_node_text(&returns, source).to_string();
                t.rsplit('.').next().map(|s| s.to_string())
            }
            _ => None,
        };
        if let Some(rt) = rt {
            if !rt.is_empty() {
                record_fn_return(&mut map, name, rt);
            }
        }
    }
    map
}

/// Extract VarType entries from a C# source tree (d.5 return propagation only).
pub(crate) fn extract_csharp_var_types(tree: &tree_sitter::Tree, source: &[u8]) -> Vec<VarType> {
    let mut var_types = Vec::new();
    let root = tree.root_node();
    let fn_return = csharp_fn_return_map(root, source);

    for node in walk_tree(root) {
        if node.kind() != "variable_declaration" {
            continue;
        }
        // Only implicitly typed locals (`var x = ...`) need inference; an explicit
        // declared type already fixes the receiver type elsewhere.
        let is_var = node
            .child_by_field_name("type")
            .map(|t| t.kind() == "implicit_type")
            .unwrap_or(false);
        if !is_var {
            continue;
        }
        for i in 0..node.named_child_count() {
            let decl = match node.named_child(i) {
                Some(c) if c.kind() == "variable_declarator" => c,
                _ => continue,
            };
            let var_name = match decl.child_by_field_name("name") {
                Some(n) => get_node_text(&n, source).to_string(),
                None => continue,
            };
            // RHS invocation among the declarator's children.
            let mut callee: Option<String> = None;
            for j in 0..decl.child_count() {
                if let Some(c) = decl.child(j) {
                    if c.kind() == "invocation_expression" {
                        if let Some(func) = c.child_by_field_name("function") {
                            if func.kind() == "identifier" {
                                callee = Some(get_node_text(&func, source).to_string());
                            } else if func.kind() == "member_access_expression" {
                                callee = func
                                    .child_by_field_name("name")
                                    .map(|n| get_node_text(&n, source).to_string());
                            }
                        }
                        break;
                    }
                }
            }
            if let Some(callee) = callee {
                if let Some(rt) = lookup_fn_return(&fn_return, &callee) {
                    let line = decl.start_position().row as u32 + 1;
                    let scope = enclosing_csharp_function_scope(&node, source);
                    var_types.push(VarType::new_with_scope(
                        var_name, rt.to_string(), "return", line, scope,
                    ));
                }
            }
        }
    }
    var_types
}

// =============================================================================
// Swift VarType extraction (FEATURE-1 d.5 Part A: declared-return propagation)
// =============================================================================
//
// As with C#, this extractor is scoped to the d.5 deliverable: `let x = make()`
// where `make() -> T` propagates T (source="return") so `x.method()` resolves
// type-scoped. Return-derived rows only; never-worse holds.

/// Determine the enclosing function scope for a Swift node. Top-level functions
/// are keyed by their simple name (matching the call handler), methods by
/// `Type.method`.
fn enclosing_swift_function_scope(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    let mut cur = node.parent();
    while let Some(p) = cur {
        if p.kind() == "function_declaration" {
            // The function name is the first `simple_identifier` child (the return
            // type is a separate `user_type` also carried under field "name").
            let mut fname: Option<String> = None;
            for i in 0..p.child_count() {
                if let Some(c) = p.child(i) {
                    if c.kind() == "simple_identifier" {
                        fname = Some(get_node_text(&c, source).to_string());
                        break;
                    }
                }
            }
            let fname = fname?;
            let mut c2 = p.parent();
            while let Some(pp) = c2 {
                if matches!(
                    pp.kind(),
                    "class_declaration" | "struct_declaration" | "enum_declaration"
                ) {
                    if let Some(cn) = pp.child_by_field_name("name") {
                        return Some(format!("{}.{}", get_node_text(&cn, source), fname));
                    }
                }
                c2 = pp.parent();
            }
            return Some(fname);
        }
        cur = p.parent();
    }
    None
}

/// FEATURE-1 d.5 (Part A): build the per-file `func simple name -> declared return
/// type` map for Swift (`func f(..) -> T`). tree-sitter-swift carries the return
/// type as a second `name:`-fielded `user_type`/`optional_type` child.
fn swift_fn_return_map(root: tree_sitter::Node, source: &[u8]) -> HashMap<String, Option<String>> {
    let mut map: HashMap<String, Option<String>> = HashMap::new();
    for node in walk_tree(root) {
        if node.kind() != "function_declaration" {
            continue;
        }
        let mut fname: Option<String> = None;
        let mut rtype: Option<String> = None;
        for i in 0..node.child_count() {
            let child = match node.child(i) {
                Some(c) => c,
                None => continue,
            };
            match child.kind() {
                "simple_identifier" if fname.is_none() => {
                    fname = Some(get_node_text(&child, source).to_string());
                }
                "user_type" | "optional_type" if rtype.is_none() => {
                    rtype = swift_type_name(&child, source);
                }
                _ => {}
            }
        }
        if let (Some(n), Some(rt)) = (fname, rtype) {
            if !rt.is_empty() {
                record_fn_return(&mut map, n, rt);
            }
        }
    }
    map
}

/// Normalise a Swift type node to a bare nominal name.
fn swift_type_name(type_node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    match type_node.kind() {
        "type_identifier" | "simple_identifier" => {
            Some(get_node_text(type_node, source).to_string())
        }
        "user_type" | "optional_type" => {
            for i in 0..type_node.named_child_count() {
                if let Some(c) = type_node.named_child(i) {
                    if let Some(r) = swift_type_name(&c, source) {
                        return Some(r);
                    }
                }
            }
            None
        }
        _ => None,
    }
}

/// Extract VarType entries from a Swift source tree (d.5 return propagation only).
pub(crate) fn extract_swift_var_types(tree: &tree_sitter::Tree, source: &[u8]) -> Vec<VarType> {
    let mut var_types = Vec::new();
    let root = tree.root_node();
    let fn_return = swift_fn_return_map(root, source);

    for node in walk_tree(root) {
        if node.kind() != "property_declaration" {
            continue;
        }
        // Variable name: `name` field is a `pattern` with a `bound_identifier`.
        let var_name = match node.child_by_field_name("name") {
            Some(pat) => pat
                .child_by_field_name("bound_identifier")
                .or_else(|| {
                    (0..pat.named_child_count())
                        .filter_map(|i| pat.named_child(i))
                        .find(|c| c.kind() == "simple_identifier")
                })
                .map(|n| get_node_text(&n, source).to_string()),
            None => None,
        };
        let var_name = match var_name {
            Some(n) if !n.is_empty() => n,
            _ => continue,
        };
        // RHS: `value` field is a `call_expression`; its first child is the callee.
        let value = match node.child_by_field_name("value") {
            Some(v) if v.kind() == "call_expression" => v,
            _ => continue,
        };
        let callee = value
            .named_child(0)
            .filter(|c| c.kind() == "simple_identifier")
            .map(|n| get_node_text(&n, source).to_string());
        if let Some(callee) = callee {
            if let Some(rt) = lookup_fn_return(&fn_return, &callee) {
                let line = node.start_position().row as u32 + 1;
                let scope = enclosing_swift_function_scope(&node, source);
                var_types.push(VarType::new_with_scope(
                    var_name, rt.to_string(), "return", line, scope,
                ));
            }
        }
    }
    var_types
}

// =============================================================================
// Lua / Luau VarType extraction
// =============================================================================
//
// FEATURE-1 stage d.4: give Lua and Luau a var_types extractor so the receiver
// type of `obj:method()` / `obj.method()` calls can be inferred. Everything here
// is tree-sitter AST-driven (node kinds + fields only) — no text/regex heuristics.
//
// Recognised, AST-driven signals (identical node kinds across the lua and luau
// grammars, plus luau-only type annotations):
//   * `local x = Mod.new()` / `Mod.create()` (factory call on a table/module
//     name)                                                     -> x : Mod
//   * `local x = setmetatable({}, {__index = Mod})`             -> x : Mod
//   * `local x = setmetatable({}, Mod)`                         -> x : Mod
//   * `local x = {}` then `setmetatable(x, {__index = Mod})`    -> x : Mod
//   * Luau `local x: T = ...`                                   -> x : T (annotation, High)
//   * Luau typed parameter `function f(x: T)`                   -> x : T (parameter, High)
//   * Luau return annotation `local function f(): T` consumed so `local y = f()`
//     inherits the declared return type                         -> y : T
//   * `function T:m(...)` — the implicit `self` receiver has type T (the
//     enclosing table), scoped to the method so `self:other()` binds to T.
//
// NEVER-WORSE: this stage only ADDS `VarType` rows. `apply_type_resolution` fills
// `receiver_type` ONLY when it was `None` (guarded), so an unresolved receiver
// stays exactly as today; a newly-typed receiver resolves type-scoped instead of
// name-conflated. No existing edge can be dropped by adding a row.

/// Lua/Luau builtin (primitive/type-checker) names that must NOT be treated as
/// project table/class types for receiver-type resolution.
const LUA_BUILTIN_TYPES: &[&str] = &[
    // Runtime value types.
    "nil",
    "boolean",
    "number",
    "string",
    "function",
    "table",
    "thread",
    "userdata",
    // Luau type-checker builtins / common scalar annotations.
    "any",
    "unknown",
    "never",
    "void",
    "bool",
    "int",
    "float",
    "true",
    "false",
];

/// Find the first direct child of `node` whose kind is `kind`.
fn lua_child_of_kind<'a>(node: &tree_sitter::Node<'a>, kind: &str) -> Option<tree_sitter::Node<'a>> {
    for i in 0..node.child_count() {
        if let Some(c) = node.child(i) {
            if c.kind() == kind {
                return Some(c);
            }
        }
    }
    None
}

/// Extract a base named-type from a Lua/Luau type-annotation AST node.
///
/// Named type references appear as a plain `identifier` in both grammars
/// (`local x: Component`, `c: Component`, `: Component`). Structural/complex
/// types (tables, unions, generics) are deliberately skipped — emitting no type
/// is strictly safe (identical to today), whereas guessing a wrong base could
/// mis-route a call.
fn lua_type_name(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    if node.kind() == "identifier" {
        let t = get_node_text(node, source).to_string();
        if t.is_empty() {
            None
        } else {
            Some(t)
        }
    } else {
        None
    }
}

/// The qualified name of a `function_declaration` name node, matching how the
/// Lua/Luau call handler keys `calls_by_func` (`foo`, `M.foo`, `T:m`).
fn lua_declaration_name(decl: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    let name_node = decl.child_by_field_name("name")?;
    match name_node.kind() {
        "identifier" | "dot_index_expression" | "method_index_expression" => {
            Some(get_node_text(&name_node, source).to_string())
        }
        _ => None,
    }
}

/// The SIMPLE (unqualified) name of a `function_declaration` — the last
/// identifier of its name node (`g`, `f` from `M.f`, `m` from `T:m`).
fn lua_simple_declaration_name(decl: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    let name_node = decl.child_by_field_name("name")?;
    match name_node.kind() {
        "identifier" => Some(get_node_text(&name_node, source).to_string()),
        "dot_index_expression" => name_node
            .child_by_field_name("field")
            .map(|f| get_node_text(&f, source).to_string()),
        "method_index_expression" => name_node
            .child_by_field_name("method")
            .map(|m| get_node_text(&m, source).to_string()),
        _ => None,
    }
}

/// Recover the name a `function_definition` (anonymous function expression) is
/// bound to: `local foo = function() end` / `foo = function() end` -> `foo`,
/// or a table-constructor field `name = function() end` -> `name`.
fn lua_anonymous_function_name(func_def: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    let mut cur = func_def.parent();
    while let Some(p) = cur {
        match p.kind() {
            "assignment_statement" => {
                if let Some(vlist) = lua_child_of_kind(&p, "variable_list") {
                    if let Some(first) = vlist.named_child(0) {
                        return Some(get_node_text(&first, source).to_string());
                    }
                }
                return None;
            }
            "field" => {
                return p
                    .child_by_field_name("name")
                    .map(|n| get_node_text(&n, source).to_string());
            }
            "function_declaration" => return lua_declaration_name(&p, source),
            _ => {}
        }
        cur = p.parent();
    }
    None
}

/// Determine the enclosing function scope for a Lua/Luau AST node.
///
/// Returns the *qualified* function name exactly as the Lua/Luau call handler
/// keys `calls_by_func`, so `find_best_vartype`'s scoped matches line up.
/// `None` at module (chunk) scope.
pub(crate) fn enclosing_lua_function_scope(
    node: &tree_sitter::Node,
    source: &[u8],
) -> Option<String> {
    let mut cur = node.parent();
    while let Some(p) = cur {
        match p.kind() {
            "function_declaration" => {
                if let Some(name) = lua_declaration_name(&p, source) {
                    return Some(name);
                }
            }
            "function_definition" => {
                if let Some(name) = lua_anonymous_function_name(&p, source) {
                    return Some(name);
                }
            }
            _ => {}
        }
        cur = p.parent();
    }
    None
}

/// Parse a `variable_list` into `(name, optional_luau_type_annotation, line)`
/// tuples. Handles plain `x`, luau-typed `x: T`, and multi-var `a, b` lists.
fn parse_lua_variable_list(
    vlist: &tree_sitter::Node,
    source: &[u8],
) -> Vec<(String, Option<String>, u32)> {
    let mut result = Vec::new();
    let count = vlist.child_count();
    let mut i = 0;
    while i < count {
        if let Some(child) = vlist.child(i) {
            if child.kind() == "identifier" {
                let name = get_node_text(&child, source).to_string();
                let line = child.start_position().row as u32 + 1;
                let mut annotation = None;
                // Luau inline annotation: `<name> : <type>`.
                if let Some(colon) = vlist.child(i + 1) {
                    if colon.kind() == ":" {
                        if let Some(type_node) = vlist.child(i + 2) {
                            annotation = lua_type_name(&type_node, source);
                            i += 2;
                        }
                    }
                }
                result.push((name, annotation, line));
            }
        }
        i += 1;
    }
    result
}

/// Extract the metatable type from a `setmetatable(_, meta)` call's `meta`
/// argument: either a bare `Mod` identifier or a `{__index = Mod}` table.
fn lua_meta_type(meta: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    match meta.kind() {
        "identifier" => {
            let t = get_node_text(meta, source).to_string();
            if t.is_empty() || LUA_BUILTIN_TYPES.contains(&t.as_str()) {
                None
            } else {
                Some(t)
            }
        }
        "table_constructor" => {
            for i in 0..meta.named_child_count() {
                if let Some(field) = meta.named_child(i) {
                    if field.kind() != "field" {
                        continue;
                    }
                    let is_index = field
                        .child_by_field_name("name")
                        .map(|k| get_node_text(&k, source) == "__index")
                        .unwrap_or(false);
                    if !is_index {
                        continue;
                    }
                    if let Some(val) = field.child_by_field_name("value") {
                        if val.kind() == "identifier" {
                            let t = get_node_text(&val, source).to_string();
                            if !t.is_empty() && !LUA_BUILTIN_TYPES.contains(&t.as_str()) {
                                return Some(t);
                            }
                        }
                    }
                }
            }
            None
        }
        _ => None,
    }
}

/// Classify the RHS `value` of a `local x = <value>` into `(type_name, source)`.
///
/// Recognises factory calls (`Mod.new()`/`Mod.create()`), `setmetatable(...)`,
/// and (luau) calls to functions with a known return annotation.
fn classify_lua_value(
    value: &tree_sitter::Node,
    source: &[u8],
    fn_return: &HashMap<String, Option<String>>,
) -> Option<(String, &'static str)> {
    if value.kind() != "function_call" {
        return None;
    }
    let name = value.child_by_field_name("name")?;
    match name.kind() {
        "identifier" => {
            let callee = get_node_text(&name, source);
            if callee == "setmetatable" {
                if let Some(args) = value.child_by_field_name("arguments") {
                    if let Some(meta) = args.named_child(1) {
                        return lua_meta_type(&meta, source).map(|t| (t, "assignment"));
                    }
                }
                return None;
            }
            // Luau: `local x = f()` where f has a known, unambiguous return type.
            if let Some(Some(rt)) = fn_return.get(callee) {
                return Some((rt.clone(), "assignment"));
            }
            None
        }
        "dot_index_expression" => {
            let table = name.child_by_field_name("table")?;
            let field = name.child_by_field_name("field")?;
            let field_txt = get_node_text(&field, source).to_string();
            // Factory / constructor call on a table/module name: `Mod.new()`.
            if table.kind() == "identifier" && (field_txt == "new" || field_txt == "create") {
                let ttext = get_node_text(&table, source).to_string();
                if !ttext.is_empty() && !LUA_BUILTIN_TYPES.contains(&ttext.as_str()) {
                    return Some((ttext, "constructor"));
                }
            }
            // Luau: `local x = Mod.f()` where Mod.f has a known return type.
            if let Some(Some(rt)) = fn_return.get(&field_txt) {
                return Some((rt.clone(), "assignment"));
            }
            None
        }
        _ => None,
    }
}

/// Handle `local x [: T] = <value>` declarations.
fn collect_lua_variable_declaration(
    decl: &tree_sitter::Node,
    source: &[u8],
    is_luau: bool,
    fn_return: &HashMap<String, Option<String>>,
    out: &mut Vec<VarType>,
) {
    let assign = match lua_child_of_kind(decl, "assignment_statement") {
        Some(a) => a,
        None => return,
    };
    let vlist = match lua_child_of_kind(&assign, "variable_list") {
        Some(v) => v,
        None => return,
    };
    let names = parse_lua_variable_list(&vlist, source);
    let values: Vec<tree_sitter::Node> = lua_child_of_kind(&assign, "expression_list")
        .map(|el| {
            (0..el.named_child_count())
                .filter_map(|i| el.named_child(i))
                .collect()
        })
        .unwrap_or_default();
    let scope = enclosing_lua_function_scope(decl, source);

    for (idx, (name, annotation, line)) in names.iter().enumerate() {
        // Luau declared annotation is authoritative (High confidence).
        if is_luau {
            if let Some(ann) = annotation {
                if !LUA_BUILTIN_TYPES.contains(&ann.as_str()) {
                    out.push(VarType::new_with_scope(
                        name.clone(),
                        ann.clone(),
                        "annotation",
                        *line,
                        scope.clone(),
                    ));
                }
                // A declared type (table or builtin) settles this var.
                continue;
            }
        }
        // Value-based inference.
        if let Some(value) = values.get(idx) {
            if let Some((type_name, source_kind)) = classify_lua_value(value, source, fn_return) {
                out.push(VarType::new_with_scope(
                    name.clone(),
                    type_name,
                    source_kind,
                    *line,
                    scope.clone(),
                ));
            }
        }
    }
}

/// Handle a standalone `setmetatable(existing_var, meta)` statement, typing the
/// already-declared `existing_var`.
fn collect_lua_standalone_setmetatable(
    call: &tree_sitter::Node,
    source: &[u8],
    out: &mut Vec<VarType>,
) {
    let name = match call.child_by_field_name("name") {
        Some(n) => n,
        None => return,
    };
    if !(name.kind() == "identifier" && get_node_text(&name, source) == "setmetatable") {
        return;
    }
    let args = match call.child_by_field_name("arguments") {
        Some(a) => a,
        None => return,
    };
    let first = match args.named_child(0) {
        Some(f) => f,
        None => return,
    };
    // Only the `setmetatable(var, meta)` form types an EXISTING variable; the
    // `setmetatable({}, meta)` form is handled at the enclosing assignment.
    if first.kind() != "identifier" {
        return;
    }
    let var_name = get_node_text(&first, source).to_string();
    let meta = match args.named_child(1) {
        Some(m) => m,
        None => return,
    };
    if let Some(type_name) = lua_meta_type(&meta, source) {
        let line = call.start_position().row as u32 + 1;
        let scope = enclosing_lua_function_scope(call, source);
        out.push(VarType::new_with_scope(
            var_name, type_name, "assignment", line, scope,
        ));
    }
}

/// Handle `function T:m(...)`: the implicit `self` receiver has type `T`, scoped
/// to the method's qualified name so `self:other()` inside it binds to `T`.
fn collect_lua_self_receiver(decl: &tree_sitter::Node, source: &[u8], out: &mut Vec<VarType>) {
    let name_node = match decl.child_by_field_name("name") {
        Some(n) if n.kind() == "method_index_expression" => n,
        _ => return,
    };
    let table = match name_node.child_by_field_name("table") {
        Some(t) if t.kind() == "identifier" => t,
        _ => return,
    };
    let type_name = get_node_text(&table, source).to_string();
    if type_name.is_empty() || LUA_BUILTIN_TYPES.contains(&type_name.as_str()) {
        return;
    }
    let scope = get_node_text(&name_node, source).to_string();
    let line = decl.start_position().row as u32 + 1;
    out.push(VarType::new_with_scope(
        "self",
        type_name,
        "parameter",
        line,
        Some(scope),
    ));
}

/// Handle a luau typed parameter `parameter` node (`x: T`).
fn collect_luau_typed_parameter(param: &tree_sitter::Node, source: &[u8], out: &mut Vec<VarType>) {
    let mut name: Option<(String, u32)> = None;
    let count = param.child_count();
    let mut i = 0;
    while i < count {
        if let Some(child) = param.child(i) {
            match child.kind() {
                "identifier" if name.is_none() => {
                    name = Some((
                        get_node_text(&child, source).to_string(),
                        child.start_position().row as u32 + 1,
                    ));
                }
                ":" => {
                    if let (Some((n, line)), Some(type_node)) = (name.clone(), param.child(i + 1)) {
                        if let Some(t) = lua_type_name(&type_node, source) {
                            if !LUA_BUILTIN_TYPES.contains(&t.as_str()) {
                                let scope = enclosing_lua_function_scope(param, source);
                                out.push(VarType::new_with_scope(n, t, "parameter", line, scope));
                            }
                        }
                    }
                    break;
                }
                _ => {}
            }
        }
        i += 1;
    }
}

/// The luau return-type annotation of a `function_declaration` (`function f(): T`).
fn luau_return_type(decl: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    let mut saw_params = false;
    let count = decl.child_count();
    let mut i = 0;
    while i < count {
        if let Some(child) = decl.child(i) {
            match child.kind() {
                "parameters" => saw_params = true,
                ":" if saw_params => {
                    if let Some(type_node) = decl.child(i + 1) {
                        return lua_type_name(&type_node, source);
                    }
                }
                "block" => break,
                _ => {}
            }
        }
        i += 1;
    }
    None
}

/// Shared Lua/Luau VarType walker. `is_luau` enables luau-only type-annotation
/// signals (declared locals, typed parameters, return-type inference).
fn extract_lua_like_var_types(
    tree: &tree_sitter::Tree,
    source: &[u8],
    is_luau: bool,
) -> Vec<VarType> {
    let root = tree.root_node();
    let mut var_types = Vec::new();

    // Pass 1 (luau only): collect function -> declared return type so that
    // `local x = f()` can inherit it. A simple name mapping to two *different*
    // return types is marked ambiguous (`None`) and never applied.
    let mut fn_return: HashMap<String, Option<String>> = HashMap::new();
    if is_luau {
        for node in walk_tree(root) {
            if node.kind() == "function_declaration" {
                if let (Some(fname), Some(rtype)) = (
                    lua_simple_declaration_name(&node, source),
                    luau_return_type(&node, source),
                ) {
                    if !LUA_BUILTIN_TYPES.contains(&rtype.as_str()) {
                        fn_return
                            .entry(fname)
                            .and_modify(|e| {
                                if e.as_deref() != Some(rtype.as_str()) {
                                    *e = None;
                                }
                            })
                            .or_insert(Some(rtype));
                    }
                }
            }
        }
    }

    for node in walk_tree(root) {
        match node.kind() {
            "variable_declaration" => {
                collect_lua_variable_declaration(&node, source, is_luau, &fn_return, &mut var_types);
            }
            "function_call" => {
                collect_lua_standalone_setmetatable(&node, source, &mut var_types);
            }
            "function_declaration" => {
                collect_lua_self_receiver(&node, source, &mut var_types);
            }
            "parameter" if is_luau => {
                collect_luau_typed_parameter(&node, source, &mut var_types);
            }
            _ => {}
        }
    }

    var_types
}

/// Extract VarType entries from a Lua source tree.
pub(crate) fn extract_lua_var_types(tree: &tree_sitter::Tree, source: &[u8]) -> Vec<VarType> {
    extract_lua_like_var_types(tree, source, false)
}

/// Extract VarType entries from a Luau source tree (adds type annotations).
pub(crate) fn extract_luau_var_types(tree: &tree_sitter::Tree, source: &[u8]) -> Vec<VarType> {
    extract_lua_like_var_types(tree, source, true)
}

// =============================================================================
// Tests (moved from builder_v2.rs during Phase 3 modularization)
// =============================================================================

#[cfg(test)]
mod tests {
    use super::super::types::parse_source;
    use super::*;
    use crate::callgraph::cross_file_types::CallType;
    use crate::callgraph::languages::base::{get_node_text, walk_tree};

    // =========================================================================
    // Python call extraction tests
    // =========================================================================

    /// Test: Call extraction in Python
    #[test]
    fn test_extract_python_calls() {
        let source = r#"
def main():
    process()
    helper.run()
"#;
        let tree = parse_source(source, "python").unwrap();
        let root = tree.root_node();
        let source_bytes = source.as_bytes();

        // Find the function node
        let mut calls = Vec::new();
        for node in walk_tree(root) {
            if node.kind() == "function_definition" {
                if let Some(name_node) = node.child_by_field_name("name") {
                    let func_name = get_node_text(&name_node, source_bytes);
                    if func_name == "main" {
                        calls = extract_python_calls(&node, source_bytes, "main");
                    }
                }
            }
        }

        assert!(!calls.is_empty(), "Should extract calls from main");

        // Check for process() call
        let process_call = calls.iter().find(|c| c.target == "process");
        assert!(process_call.is_some(), "Should find process() call");
        assert_eq!(process_call.unwrap().call_type, CallType::Direct);

        // Check for helper.run() call
        let helper_call = calls.iter().find(|c| c.target == "run");
        assert!(helper_call.is_some(), "Should find helper.run() call");
        assert_eq!(helper_call.unwrap().call_type, CallType::Method);
        assert_eq!(helper_call.unwrap().receiver, Some("helper".to_string()));
    }

    // ==========================================================================
    // TypeScript/JavaScript VarType extraction tests
    // ==========================================================================

    #[test]
    fn test_extract_ts_var_types_new_expression() {
        let source = r#"
const router = new Router();
const app = new Application();
"#;
        let tree = parse_source(source, "typescript").unwrap();
        let var_types = extract_ts_var_types(&tree, source.as_bytes());

        assert_eq!(var_types.len(), 2);
        assert_eq!(var_types[0].var_name, "router");
        assert_eq!(var_types[0].type_name, "Router");
        assert_eq!(var_types[0].source, "assignment");
        assert_eq!(var_types[1].var_name, "app");
        assert_eq!(var_types[1].type_name, "Application");
    }

    #[test]
    fn test_extract_ts_var_types_type_annotation() {
        let source = r#"
let user: User;
const handler: RequestHandler = createHandler();
"#;
        let tree = parse_source(source, "typescript").unwrap();
        let var_types = extract_ts_var_types(&tree, source.as_bytes());

        let user_vt = var_types.iter().find(|v| v.var_name == "user").unwrap();
        assert_eq!(user_vt.type_name, "User");
        assert_eq!(user_vt.source, "annotation");

        let handler_vt = var_types.iter().find(|v| v.var_name == "handler").unwrap();
        assert_eq!(handler_vt.type_name, "RequestHandler");
        assert_eq!(handler_vt.source, "annotation");
    }

    #[test]
    fn test_extract_ts_var_types_typed_parameters() {
        let source = r#"
function processUser(user: User, config: AppConfig) {
    console.log(user);
}
"#;
        let tree = parse_source(source, "typescript").unwrap();
        let var_types = extract_ts_var_types(&tree, source.as_bytes());

        assert_eq!(var_types.len(), 2);

        let user_vt = var_types.iter().find(|v| v.var_name == "user").unwrap();
        assert_eq!(user_vt.type_name, "User");
        assert_eq!(user_vt.source, "parameter");
        assert_eq!(user_vt.scope, Some("processUser".to_string()));

        let config_vt = var_types.iter().find(|v| v.var_name == "config").unwrap();
        assert_eq!(config_vt.type_name, "AppConfig");
        assert_eq!(config_vt.source, "parameter");
    }

    #[test]
    fn test_extract_ts_var_types_builtin_types_skipped() {
        let source = r#"
const name: string = "hello";
const count: number = 42;
const flag: boolean = true;
const arr: Array<string> = [];
const promise: Promise<void> = fetch("/");
"#;
        let tree = parse_source(source, "typescript").unwrap();
        let var_types = extract_ts_var_types(&tree, source.as_bytes());

        for vt in &var_types {
            assert_eq!(
                vt.source, "literal",
                "Only literal sources expected, got {} for {}",
                vt.source, vt.var_name
            );
        }
    }

    #[test]
    fn test_extract_ts_var_types_literals() {
        let source = r#"
const s = "hello";
const n = 42;
const b = true;
const a = [1, 2, 3];
const o = {key: "val"};
const r = /regex/;
const nu = null;
"#;
        let tree = parse_source(source, "typescript").unwrap();
        let var_types = extract_ts_var_types(&tree, source.as_bytes());

        let find = |name: &str| var_types.iter().find(|v| v.var_name == name).unwrap();

        assert_eq!(find("s").type_name, "string");
        assert_eq!(find("s").source, "literal");
        assert_eq!(find("n").type_name, "number");
        assert_eq!(find("b").type_name, "boolean");
        assert_eq!(find("a").type_name, "Array");
        assert_eq!(find("o").type_name, "Object");
        assert_eq!(find("r").type_name, "RegExp");
        assert_eq!(find("nu").type_name, "null");
    }

    #[test]
    fn test_extract_ts_var_types_class_method_scope() {
        let source = r#"
class UserService {
    processUser(user: User) {
        const db = new Database();
    }
}
"#;
        let tree = parse_source(source, "typescript").unwrap();
        let var_types = extract_ts_var_types(&tree, source.as_bytes());

        let user_vt = var_types.iter().find(|v| v.var_name == "user").unwrap();
        assert_eq!(user_vt.scope, Some("UserService.processUser".to_string()));

        let db_vt = var_types.iter().find(|v| v.var_name == "db").unwrap();
        assert_eq!(db_vt.type_name, "Database");
        assert_eq!(db_vt.scope, Some("UserService.processUser".to_string()));
    }

    #[test]
    fn test_extract_ts_var_types_as_expression() {
        let source = r#"
const animal = getAnimal() as Animal;
"#;
        let tree = parse_source(source, "typescript").unwrap();
        let var_types = extract_ts_var_types(&tree, source.as_bytes());

        let animal_vt = var_types.iter().find(|v| v.var_name == "animal").unwrap();
        assert_eq!(animal_vt.type_name, "Animal");
        assert_eq!(animal_vt.source, "assertion");
    }

    #[test]
    fn test_extract_ts_var_types_new_with_annotation() {
        let source = r#"
const svc: Service = new ServiceImpl();
"#;
        let tree = parse_source(source, "typescript").unwrap();
        let var_types = extract_ts_var_types(&tree, source.as_bytes());

        let assignment = var_types.iter().find(|v| v.source == "assignment").unwrap();
        assert_eq!(assignment.type_name, "ServiceImpl");

        let annotation = var_types.iter().find(|v| v.source == "annotation").unwrap();
        assert_eq!(annotation.type_name, "Service");
    }

    // =========================================================================
    // Java VarType extraction tests
    // =========================================================================

    #[test]
    fn test_extract_java_var_types_constructor() {
        let source = r#"
class App {
    void run() {
        Dog dog = new Dog();
        Cat cat = new Cat("whiskers");
    }
}
"#;
        let tree = parse_source(source, "java").unwrap();
        let var_types = extract_java_var_types(&tree, source.as_bytes());

        let dog_vt = var_types.iter().find(|v| v.var_name == "dog").unwrap();
        assert_eq!(dog_vt.type_name, "Dog");
        assert_eq!(dog_vt.source, "constructor");
        assert_eq!(dog_vt.scope, Some("App.run".to_string()));

        let cat_vt = var_types.iter().find(|v| v.var_name == "cat").unwrap();
        assert_eq!(cat_vt.type_name, "Cat");
        assert_eq!(cat_vt.source, "constructor");
    }

    #[test]
    fn test_extract_java_var_types_annotation() {
        let source = r#"
class App {
    void run() {
        Dog dog;
        Animal animal = getAnimal();
    }
}
"#;
        let tree = parse_source(source, "java").unwrap();
        let var_types = extract_java_var_types(&tree, source.as_bytes());

        let dog_vt = var_types.iter().find(|v| v.var_name == "dog").unwrap();
        assert_eq!(dog_vt.type_name, "Dog");
        assert_eq!(dog_vt.source, "annotation");

        let animal_vt = var_types.iter().find(|v| v.var_name == "animal").unwrap();
        assert_eq!(animal_vt.type_name, "Animal");
        assert_eq!(animal_vt.source, "annotation");
    }

    #[test]
    fn test_extract_java_var_types_builtin_types_skipped() {
        let source = r#"
class App {
    void run() {
        String name = "hello";
        int count = 5;
        Integer boxed = 10;
        boolean flag = true;
        Object obj = new Object();
        Dog dog = new Dog();
    }
}
"#;
        let tree = parse_source(source, "java").unwrap();
        let var_types = extract_java_var_types(&tree, source.as_bytes());

        assert_eq!(var_types.len(), 1);
        assert_eq!(var_types[0].var_name, "dog");
        assert_eq!(var_types[0].type_name, "Dog");
    }

    #[test]
    fn test_extract_java_var_types_parameters() {
        let source = r#"
class Service {
    void process(Dog dog, Cat cat, String name) {
        dog.bark();
    }
}
"#;
        let tree = parse_source(source, "java").unwrap();
        let var_types = extract_java_var_types(&tree, source.as_bytes());

        assert_eq!(var_types.len(), 2);

        let dog_vt = var_types.iter().find(|v| v.var_name == "dog").unwrap();
        assert_eq!(dog_vt.type_name, "Dog");
        assert_eq!(dog_vt.source, "parameter");
        assert_eq!(dog_vt.scope, Some("Service.process".to_string()));

        let cat_vt = var_types.iter().find(|v| v.var_name == "cat").unwrap();
        assert_eq!(cat_vt.type_name, "Cat");
        assert_eq!(cat_vt.source, "parameter");
    }

    #[test]
    fn test_extract_java_var_types_field() {
        let source = r#"
class App {
    private Animal animal;
    private Dog dog = new Dog();
}
"#;
        let tree = parse_source(source, "java").unwrap();
        let var_types = extract_java_var_types(&tree, source.as_bytes());

        let animal_vt = var_types.iter().find(|v| v.var_name == "animal").unwrap();
        assert_eq!(animal_vt.type_name, "Animal");
        assert_eq!(animal_vt.source, "annotation");
        assert_eq!(animal_vt.scope, Some("App".to_string()));

        let dog_vt = var_types.iter().find(|v| v.var_name == "dog").unwrap();
        assert_eq!(dog_vt.type_name, "Dog");
        assert_eq!(dog_vt.source, "constructor");
        assert_eq!(dog_vt.scope, Some("App".to_string()));
    }

    #[test]
    fn test_extract_java_var_types_generic() {
        let source = r#"
class App {
    void run() {
        ArrayList<Dog> dogs = new ArrayList<>();
        HashMap<String, Cat> catMap = new HashMap<>();
    }
}
"#;
        let tree = parse_source(source, "java").unwrap();
        let var_types = extract_java_var_types(&tree, source.as_bytes());

        let dogs_vt = var_types.iter().find(|v| v.var_name == "dogs").unwrap();
        assert_eq!(dogs_vt.type_name, "ArrayList");
        assert_eq!(dogs_vt.source, "constructor");

        let cat_map_vt = var_types.iter().find(|v| v.var_name == "catMap").unwrap();
        assert_eq!(cat_map_vt.type_name, "HashMap");
        assert_eq!(cat_map_vt.source, "constructor");
    }

    #[test]
    fn test_extract_java_var_types_var_keyword() {
        let source = r#"
class App {
    void run() {
        var dog = new Dog();
        var name = "hello";
    }
}
"#;
        let tree = parse_source(source, "java").unwrap();
        let var_types = extract_java_var_types(&tree, source.as_bytes());

        let dog_vt = var_types.iter().find(|v| v.var_name == "dog").unwrap();
        assert_eq!(dog_vt.type_name, "Dog");
        assert_eq!(dog_vt.source, "constructor");

        assert!(!var_types.iter().any(|v| v.var_name == "name"));
    }

    #[test]
    fn test_extract_java_var_types_enhanced_for() {
        let source = r#"
class App {
    void run() {
        for (Dog dog : dogs) {
            dog.bark();
        }
    }
}
"#;
        let tree = parse_source(source, "java").unwrap();
        let var_types = extract_java_var_types(&tree, source.as_bytes());

        let dog_vt = var_types.iter().find(|v| v.var_name == "dog").unwrap();
        assert_eq!(dog_vt.type_name, "Dog");
        assert_eq!(dog_vt.source, "annotation");
        assert_eq!(dog_vt.scope, Some("App.run".to_string()));
    }

    #[test]
    fn test_extract_java_var_types_scope() {
        let source = r#"
class MyClass {
    void methodA() {
        Dog dog = new Dog();
    }
    void methodB(Cat cat) {
        cat.meow();
    }
}
"#;
        let tree = parse_source(source, "java").unwrap();
        let var_types = extract_java_var_types(&tree, source.as_bytes());

        let dog_vt = var_types.iter().find(|v| v.var_name == "dog").unwrap();
        assert_eq!(dog_vt.scope, Some("MyClass.methodA".to_string()));

        let cat_vt = var_types.iter().find(|v| v.var_name == "cat").unwrap();
        assert_eq!(cat_vt.scope, Some("MyClass.methodB".to_string()));
    }

    // ========================================================================
    // Rust VarType extraction tests
    // ========================================================================

    #[test]
    fn test_extract_rust_var_types_scoped_constructor() {
        let source = r#"
fn main() {
    let dog = Dog::new();
    let cat = Cat::with_name("whiskers");
}
"#;
        let tree = parse_source(source, "rust").unwrap();
        let var_types = extract_rust_var_types(&tree, source.as_bytes());

        let dog_vt = var_types.iter().find(|v| v.var_name == "dog").unwrap();
        assert_eq!(dog_vt.type_name, "Dog");
        assert_eq!(dog_vt.source, "constructor");
        assert_eq!(dog_vt.scope, Some("main".to_string()));

        let cat_vt = var_types.iter().find(|v| v.var_name == "cat").unwrap();
        assert_eq!(cat_vt.type_name, "Cat");
        assert_eq!(cat_vt.source, "constructor");
    }

    #[test]
    fn test_extract_rust_var_types_struct_expression() {
        let source = r#"
fn create() {
    let animal = Animal { name: "Rex".to_string(), age: 5 };
}
"#;
        let tree = parse_source(source, "rust").unwrap();
        let var_types = extract_rust_var_types(&tree, source.as_bytes());

        let vt = var_types.iter().find(|v| v.var_name == "animal").unwrap();
        assert_eq!(vt.type_name, "Animal");
        assert_eq!(vt.source, "constructor");
        assert_eq!(vt.scope, Some("create".to_string()));
    }

    #[test]
    fn test_extract_rust_var_types_type_annotation() {
        let source = r#"
fn process() {
    let a: Animal = get_animal();
}
"#;
        let tree = parse_source(source, "rust").unwrap();
        let var_types = extract_rust_var_types(&tree, source.as_bytes());

        let vt = var_types.iter().find(|v| v.var_name == "a").unwrap();
        assert_eq!(vt.type_name, "Animal");
        assert_eq!(vt.source, "annotation");
    }

    #[test]
    fn test_extract_rust_var_types_reference_type() {
        let source = r#"
fn process(animal: &Animal) {
    let b: &mut Dog = get_dog();
}
"#;
        let tree = parse_source(source, "rust").unwrap();
        let var_types = extract_rust_var_types(&tree, source.as_bytes());

        let animal_vt = var_types.iter().find(|v| v.var_name == "animal").unwrap();
        assert_eq!(animal_vt.type_name, "Animal");
        assert_eq!(animal_vt.source, "parameter");

        let dog_vt = var_types.iter().find(|v| v.var_name == "b").unwrap();
        assert_eq!(dog_vt.type_name, "Dog");
        assert_eq!(dog_vt.source, "annotation");
    }

    #[test]
    fn test_extract_rust_var_types_builtin_types_skipped() {
        let source = r#"
fn main() {
    let name: String = "hello".to_string();
    let count: i32 = 5;
    let flag: bool = true;
    let items: Vec<i32> = vec![1, 2, 3];
    let dog = Dog::new();
}
"#;
        let tree = parse_source(source, "rust").unwrap();
        let var_types = extract_rust_var_types(&tree, source.as_bytes());

        assert_eq!(var_types.len(), 1);
        assert_eq!(var_types[0].var_name, "dog");
        assert_eq!(var_types[0].type_name, "Dog");
    }

    #[test]
    fn test_extract_rust_var_types_parameters() {
        let source = r#"
fn process(dog: Dog, cat: &Cat, name: String) {
    dog.bark();
}
"#;
        let tree = parse_source(source, "rust").unwrap();
        let var_types = extract_rust_var_types(&tree, source.as_bytes());

        assert_eq!(var_types.len(), 2);

        let dog_vt = var_types.iter().find(|v| v.var_name == "dog").unwrap();
        assert_eq!(dog_vt.type_name, "Dog");
        assert_eq!(dog_vt.source, "parameter");
        assert_eq!(dog_vt.scope, Some("process".to_string()));

        let cat_vt = var_types.iter().find(|v| v.var_name == "cat").unwrap();
        assert_eq!(cat_vt.type_name, "Cat");
        assert_eq!(cat_vt.source, "parameter");
    }

    #[test]
    fn test_extract_rust_var_types_impl_scope() {
        let source = r#"
struct MyStruct;

impl MyStruct {
    fn new() -> Self {
        let config = Config::default();
        MyStruct
    }

    fn process(&self, handler: Handler) {
        handler.run();
    }
}
"#;
        let tree = parse_source(source, "rust").unwrap();
        let var_types = extract_rust_var_types(&tree, source.as_bytes());

        let config_vt = var_types.iter().find(|v| v.var_name == "config").unwrap();
        assert_eq!(config_vt.type_name, "Config");
        assert_eq!(config_vt.source, "constructor");
        assert_eq!(config_vt.scope, Some("MyStruct.new".to_string()));

        let handler_vt = var_types.iter().find(|v| v.var_name == "handler").unwrap();
        assert_eq!(handler_vt.type_name, "Handler");
        assert_eq!(handler_vt.source, "parameter");
        assert_eq!(handler_vt.scope, Some("MyStruct.process".to_string()));
    }

    #[test]
    fn test_extract_rust_var_types_constructor_preferred_over_annotation() {
        let source = r#"
fn main() {
    let dog: Dog = Dog::new();
}
"#;
        let tree = parse_source(source, "rust").unwrap();
        let var_types = extract_rust_var_types(&tree, source.as_bytes());

        let dog_entries: Vec<_> = var_types.iter().filter(|v| v.var_name == "dog").collect();
        assert_eq!(dog_entries.len(), 1);
        assert_eq!(dog_entries[0].source, "constructor");
    }

    #[test]
    fn test_extract_rust_var_types_underscore_vars_skipped() {
        let source = r#"
fn main() {
    let _unused = Dog::new();
    let _: Animal = get_animal();
}
"#;
        let tree = parse_source(source, "rust").unwrap();
        let var_types = extract_rust_var_types(&tree, source.as_bytes());

        assert_eq!(var_types.len(), 0);
    }

    // =========================================================================
    // Kotlin VarType extraction tests
    // =========================================================================

    #[test]
    fn test_extract_kotlin_var_types_constructor_call() {
        let source = r#"
fun main() {
    val dog = Dog("Rex")
    val handler = Handler()
}
"#;
        let tree = parse_source(source, "kotlin").unwrap();
        let var_types = extract_kotlin_var_types(&tree, source.as_bytes());

        let dog_vt = var_types.iter().find(|v| v.var_name == "dog");
        assert!(
            dog_vt.is_some(),
            "Should find 'dog' var type. Found: {:?}",
            var_types
        );
        let dog_vt = dog_vt.unwrap();
        assert_eq!(dog_vt.type_name, "Dog");
        assert_eq!(dog_vt.source, "assignment");

        let handler_vt = var_types.iter().find(|v| v.var_name == "handler");
        assert!(
            handler_vt.is_some(),
            "Should find 'handler' var type. Found: {:?}",
            var_types
        );
        let handler_vt = handler_vt.unwrap();
        assert_eq!(handler_vt.type_name, "Handler");
        assert_eq!(handler_vt.source, "assignment");
    }

    #[test]
    fn test_extract_kotlin_var_types_type_annotation() {
        let source = r#"
fun main() {
    val repo: Repository = getRepo()
    val service: Service = Service()
}
"#;
        let tree = parse_source(source, "kotlin").unwrap();
        let var_types = extract_kotlin_var_types(&tree, source.as_bytes());

        let repo_vt = var_types.iter().find(|v| v.var_name == "repo");
        assert!(
            repo_vt.is_some(),
            "Should find 'repo' var type. Found: {:?}",
            var_types
        );
        let repo_vt = repo_vt.unwrap();
        assert_eq!(repo_vt.type_name, "Repository");
        assert_eq!(repo_vt.source, "annotation");

        let service_vt = var_types.iter().find(|v| v.var_name == "service");
        assert!(
            service_vt.is_some(),
            "Should find 'service' var type. Found: {:?}",
            var_types
        );
        assert_eq!(service_vt.unwrap().source, "annotation");
    }

    #[test]
    fn test_extract_kotlin_var_types_nullable_type() {
        let source = r#"
fun main() {
    val maybe: Dog? = findDog()
}
"#;
        let tree = parse_source(source, "kotlin").unwrap();
        let var_types = extract_kotlin_var_types(&tree, source.as_bytes());

        let maybe_vt = var_types.iter().find(|v| v.var_name == "maybe");
        assert!(
            maybe_vt.is_some(),
            "Should find 'maybe' var type. Found: {:?}",
            var_types
        );
        let maybe_vt = maybe_vt.unwrap();
        assert_eq!(maybe_vt.type_name, "Dog");
        assert_eq!(maybe_vt.source, "annotation");
    }

    #[test]
    fn test_extract_kotlin_var_types_function_parameters() {
        let source = r#"
fun process(dog: Dog, name: String) {
    println(dog)
}
"#;
        let tree = parse_source(source, "kotlin").unwrap();
        let var_types = extract_kotlin_var_types(&tree, source.as_bytes());

        let dog_vt = var_types.iter().find(|v| v.var_name == "dog");
        assert!(
            dog_vt.is_some(),
            "Should find 'dog' parameter. Found: {:?}",
            var_types
        );
        let dog_vt = dog_vt.unwrap();
        assert_eq!(dog_vt.type_name, "Dog");
        assert_eq!(dog_vt.source, "parameter");
        assert_eq!(dog_vt.scope, Some("process".to_string()));

        let string_vt = var_types.iter().find(|v| v.var_name == "name");
        assert!(
            string_vt.is_none(),
            "String param should be filtered. Found: {:?}",
            var_types
        );
    }

    #[test]
    fn test_extract_kotlin_var_types_class_parameters() {
        let source = r#"
class Service(val repo: Repository, val handler: Handler)
"#;
        let tree = parse_source(source, "kotlin").unwrap();
        let var_types = extract_kotlin_var_types(&tree, source.as_bytes());

        let repo_vt = var_types.iter().find(|v| v.var_name == "repo");
        assert!(
            repo_vt.is_some(),
            "Should find 'repo' class param. Found: {:?}",
            var_types
        );
        let repo_vt = repo_vt.unwrap();
        assert_eq!(repo_vt.type_name, "Repository");
        assert_eq!(repo_vt.source, "parameter");

        let handler_vt = var_types.iter().find(|v| v.var_name == "handler");
        assert!(
            handler_vt.is_some(),
            "Should find 'handler' class param. Found: {:?}",
            var_types
        );
        assert_eq!(handler_vt.unwrap().type_name, "Handler");
    }

    #[test]
    fn test_extract_kotlin_var_types_builtin_types_skipped() {
        let source = r#"
fun main() {
    val name: String = "hello"
    val count: Int = 42
    val flag: Boolean = true
    val items: List<String> = listOf()
    val map: Map<String, Int> = mapOf()
}
"#;
        let tree = parse_source(source, "kotlin").unwrap();
        let var_types = extract_kotlin_var_types(&tree, source.as_bytes());

        assert_eq!(
            var_types.len(),
            0,
            "Builtin types should be skipped. Found: {:?}",
            var_types
        );
    }

    #[test]
    fn test_extract_kotlin_var_types_class_method_scope() {
        let source = r#"
class Controller {
    fun handle(req: Request) {
        val service = Service()
    }
}
"#;
        let tree = parse_source(source, "kotlin").unwrap();
        let var_types = extract_kotlin_var_types(&tree, source.as_bytes());

        let req_vt = var_types.iter().find(|v| v.var_name == "req");
        assert!(
            req_vt.is_some(),
            "Should find 'req' param. Found: {:?}",
            var_types
        );
        assert_eq!(req_vt.unwrap().scope, Some("Controller.handle".to_string()));

        let service_vt = var_types.iter().find(|v| v.var_name == "service");
        assert!(
            service_vt.is_some(),
            "Should find 'service' var. Found: {:?}",
            var_types
        );
        assert_eq!(
            service_vt.unwrap().scope,
            Some("Controller.handle".to_string())
        );
    }

    // =========================================================================
    // PHP VarType extraction tests
    // =========================================================================

    #[test]
    fn test_extract_php_var_types_constructor() {
        let source = r#"<?php
$logger = new Logger();
$handler = new RequestHandler();
"#;
        let tree = parse_source(source, "php").unwrap();
        let var_types = extract_php_var_types(&tree, source.as_bytes());

        assert_eq!(
            var_types.len(),
            2,
            "Expected 2 constructor var types, got {:?}",
            var_types
        );
        assert_eq!(var_types[0].var_name, "logger");
        assert_eq!(var_types[0].type_name, "Logger");
        assert_eq!(var_types[0].source, "constructor");
        assert_eq!(var_types[1].var_name, "handler");
        assert_eq!(var_types[1].type_name, "RequestHandler");
        assert_eq!(var_types[1].source, "constructor");
    }

    #[test]
    fn test_extract_php_var_types_typed_parameters() {
        let source = r#"<?php
function process(Request $request, Config $config) {
    return null;
}
"#;
        let tree = parse_source(source, "php").unwrap();
        let var_types = extract_php_var_types(&tree, source.as_bytes());

        assert_eq!(
            var_types.len(),
            2,
            "Expected 2 parameter var types, got {:?}",
            var_types
        );

        let req_vt = var_types.iter().find(|v| v.var_name == "request").unwrap();
        assert_eq!(req_vt.type_name, "Request");
        assert_eq!(req_vt.source, "parameter");
        assert_eq!(req_vt.scope, Some("process".to_string()));

        let cfg_vt = var_types.iter().find(|v| v.var_name == "config").unwrap();
        assert_eq!(cfg_vt.type_name, "Config");
        assert_eq!(cfg_vt.source, "parameter");
    }

    #[test]
    fn test_extract_php_var_types_nullable_parameter() {
        let source = r#"<?php
function setup(?Database $db) {
    return null;
}
"#;
        let tree = parse_source(source, "php").unwrap();
        let var_types = extract_php_var_types(&tree, source.as_bytes());

        assert_eq!(
            var_types.len(),
            1,
            "Expected 1 nullable parameter, got {:?}",
            var_types
        );
        assert_eq!(var_types[0].var_name, "db");
        assert_eq!(var_types[0].type_name, "Database");
        assert_eq!(var_types[0].source, "parameter");
    }

    #[test]
    fn test_extract_php_var_types_property_declaration() {
        let source = r#"<?php
class UserService {
    private UserRepository $repo;
    protected Logger $logger;
}
"#;
        let tree = parse_source(source, "php").unwrap();
        let var_types = extract_php_var_types(&tree, source.as_bytes());

        assert_eq!(
            var_types.len(),
            2,
            "Expected 2 property var types, got {:?}",
            var_types
        );

        let repo_vt = var_types.iter().find(|v| v.var_name == "repo").unwrap();
        assert_eq!(repo_vt.type_name, "UserRepository");
        assert_eq!(repo_vt.source, "annotation");

        let logger_vt = var_types.iter().find(|v| v.var_name == "logger").unwrap();
        assert_eq!(logger_vt.type_name, "Logger");
        assert_eq!(logger_vt.source, "annotation");
    }

    #[test]
    fn test_extract_php_var_types_builtin_types_skipped() {
        let source = r#"<?php
function example(string $name, int $count, array $items, bool $flag) {
    return null;
}
class Foo {
    private string $label;
    protected int $id;
}
$x = new stdClass();
"#;
        let tree = parse_source(source, "php").unwrap();
        let var_types = extract_php_var_types(&tree, source.as_bytes());

        for vt in &var_types {
            assert!(
                !["string", "int", "float", "bool", "array", "object", "mixed", "void", "null"]
                    .contains(&vt.type_name.as_str()),
                "Builtin type '{}' should have been filtered, got {:?}",
                vt.type_name,
                vt
            );
        }
    }

    #[test]
    fn test_extract_php_var_types_method_scope() {
        let source = r#"<?php
class Controller {
    public function handle(Request $req) {
        $service = new UserService();
        return $service->process($req);
    }
}
"#;
        let tree = parse_source(source, "php").unwrap();
        let var_types = extract_php_var_types(&tree, source.as_bytes());

        let req_vt = var_types.iter().find(|v| v.var_name == "req");
        assert!(
            req_vt.is_some(),
            "Should find 'req' param. Found: {:?}",
            var_types
        );
        assert_eq!(req_vt.unwrap().scope, Some("Controller.handle".to_string()));

        let service_vt = var_types.iter().find(|v| v.var_name == "service");
        assert!(
            service_vt.is_some(),
            "Should find 'service' var. Found: {:?}",
            var_types
        );
        assert_eq!(service_vt.unwrap().type_name, "UserService");
        assert_eq!(service_vt.unwrap().source, "constructor");
        assert_eq!(
            service_vt.unwrap().scope,
            Some("Controller.handle".to_string())
        );
    }

    #[test]
    fn test_extract_php_var_types_comprehensive() {
        let source = r#"<?php
class UserService {
    private UserRepository $repo;

    public function __construct(UserRepository $repo) {
        $this->repo = $repo;
        $logger = new Logger();
    }

    public function process(Request $request): Response {
        $handler = new RequestHandler();
        return $handler->handle($request);
    }
}

function standalone(?Config $config) {
    $db = new Database();
}

$top = new TopLevel();
"#;
        let tree = parse_source(source, "php").unwrap();
        let var_types = extract_php_var_types(&tree, source.as_bytes());

        let names: Vec<&str> = var_types.iter().map(|v| v.var_name.as_str()).collect();
        assert!(
            names.contains(&"repo"),
            "Missing 'repo'. Found: {:?}",
            names
        );
        assert!(
            names.contains(&"logger"),
            "Missing 'logger'. Found: {:?}",
            names
        );
        assert!(
            names.contains(&"request"),
            "Missing 'request'. Found: {:?}",
            names
        );
        assert!(
            names.contains(&"handler"),
            "Missing 'handler'. Found: {:?}",
            names
        );
        assert!(
            names.contains(&"config"),
            "Missing 'config'. Found: {:?}",
            names
        );
        assert!(names.contains(&"db"), "Missing 'db'. Found: {:?}", names);
        assert!(names.contains(&"top"), "Missing 'top'. Found: {:?}", names);

        let top_vt = var_types.iter().find(|v| v.var_name == "top").unwrap();
        assert_eq!(top_vt.type_name, "TopLevel");
        assert_eq!(top_vt.source, "constructor");
        assert_eq!(top_vt.scope, None);

        let config_vt = var_types.iter().find(|v| v.var_name == "config").unwrap();
        assert_eq!(config_vt.type_name, "Config");
        assert_eq!(config_vt.source, "parameter");
        assert_eq!(config_vt.scope, Some("standalone".to_string()));
    }

    // ==========================================================================
    // Lua / Luau VarType extraction tests (FEATURE-1 stage d.4)
    // ==========================================================================

    /// `local x = Mod.new()` / `Mod.create()` -> x : Mod (RTA factory).
    #[test]
    fn test_extract_lua_var_types_factory_new() {
        let source = r#"
local Process = require('process')
local proc = Process.new()
local other = Process.create()
"#;
        let tree = parse_source(source, "lua").unwrap();
        let var_types = extract_lua_var_types(&tree, source.as_bytes());

        // `Process = require(...)` must NOT be typed (require is not a factory).
        assert!(
            var_types.iter().all(|v| v.var_name != "Process"),
            "require() result must not be typed, got {:?}",
            var_types
        );

        let proc = var_types.iter().find(|v| v.var_name == "proc").unwrap();
        assert_eq!(proc.type_name, "Process");
        assert_eq!(proc.source, "constructor");
        assert_eq!(proc.scope, None);

        let other = var_types.iter().find(|v| v.var_name == "other").unwrap();
        assert_eq!(other.type_name, "Process");
        assert_eq!(other.source, "constructor");
    }

    /// `local x = setmetatable({}, {__index = Mod})` and
    /// `local x = setmetatable({}, Mod)` -> x : Mod.
    #[test]
    fn test_extract_lua_var_types_setmetatable_forms() {
        let source = r#"
local a = setmetatable({}, {__index = Widget})
local b = setmetatable({}, Widget)
"#;
        let tree = parse_source(source, "lua").unwrap();
        let var_types = extract_lua_var_types(&tree, source.as_bytes());

        let a = var_types.iter().find(|v| v.var_name == "a").unwrap();
        assert_eq!(a.type_name, "Widget");
        assert_eq!(a.source, "assignment");

        let b = var_types.iter().find(|v| v.var_name == "b").unwrap();
        assert_eq!(b.type_name, "Widget");
        assert_eq!(b.source, "assignment");
    }

    /// `local x = {}` then a standalone `setmetatable(x, {__index = Mod})`
    /// -> x : Mod (types the already-declared variable).
    #[test]
    fn test_extract_lua_var_types_standalone_setmetatable() {
        let source = r#"
local c = {}
setmetatable(c, {__index = Gadget})
"#;
        let tree = parse_source(source, "lua").unwrap();
        let var_types = extract_lua_var_types(&tree, source.as_bytes());

        let c = var_types.iter().find(|v| v.var_name == "c").unwrap();
        assert_eq!(c.type_name, "Gadget");
        assert_eq!(c.source, "assignment");
        // Recorded at the setmetatable statement (line 3, 1-indexed).
        assert_eq!(c.line, 3);
    }

    /// Inside `function T:m(...)` the implicit `self` receiver has type `T`,
    /// scoped to the method's qualified name (`T:m`).
    #[test]
    fn test_extract_lua_var_types_self_receiver() {
        let source = r#"
function Process:initialize()
  self:setup()
end
"#;
        let tree = parse_source(source, "lua").unwrap();
        let var_types = extract_lua_var_types(&tree, source.as_bytes());

        let self_vt = var_types
            .iter()
            .find(|v| v.var_name == "self")
            .expect("self should be typed inside a colon method");
        assert_eq!(self_vt.type_name, "Process");
        assert_eq!(self_vt.source, "parameter");
        assert_eq!(self_vt.scope, Some("Process:initialize".to_string()));
    }

    /// Luau `local x: T = ...` -> x : T (annotation, High); builtin scalar
    /// annotations (`number`) are skipped.
    #[test]
    fn test_extract_luau_var_types_annotation() {
        let source = r#"
local x: Component = nil
local n: number = 0
"#;
        let tree = parse_source(source, "luau").unwrap();
        let var_types = extract_luau_var_types(&tree, source.as_bytes());

        let x = var_types.iter().find(|v| v.var_name == "x").unwrap();
        assert_eq!(x.type_name, "Component");
        assert_eq!(x.source, "annotation");

        assert!(
            var_types.iter().all(|v| v.var_name != "n"),
            "builtin `number` annotation must be skipped, got {:?}",
            var_types
        );
    }

    /// Luau typed parameter `function f(x: T)` -> x : T (parameter, scoped to f).
    #[test]
    fn test_extract_luau_var_types_typed_parameter() {
        let source = r#"
function f(c: Component)
  c:setState()
end
"#;
        let tree = parse_source(source, "luau").unwrap();
        let var_types = extract_luau_var_types(&tree, source.as_bytes());

        let c = var_types.iter().find(|v| v.var_name == "c").unwrap();
        assert_eq!(c.type_name, "Component");
        assert_eq!(c.source, "parameter");
        assert_eq!(c.scope, Some("f".to_string()));
    }

    /// Luau `local function g(): T` return annotation lets `local y = g()`
    /// inherit the declared return type.
    #[test]
    fn test_extract_luau_var_types_return_annotation_inferred() {
        let source = r#"
local function makeThing(): Thing
  return nil
end
local w = makeThing()
"#;
        let tree = parse_source(source, "luau").unwrap();
        let var_types = extract_luau_var_types(&tree, source.as_bytes());

        let w = var_types.iter().find(|v| v.var_name == "w").unwrap();
        assert_eq!(w.type_name, "Thing");
        assert_eq!(w.source, "assignment");
    }

    /// Lua is NOT affected by luau-only annotation signals: a plain
    /// `local x = Mod.new()` still types, but no annotation/return inference.
    #[test]
    fn test_extract_lua_var_types_ignores_luau_only_signals() {
        // Return annotation must not be consumed for plain Lua.
        let source = r#"
local proc = Factory.new()
"#;
        let tree = parse_source(source, "lua").unwrap();
        let var_types = extract_lua_var_types(&tree, source.as_bytes());
        let proc = var_types.iter().find(|v| v.var_name == "proc").unwrap();
        assert_eq!(proc.type_name, "Factory");
        assert_eq!(proc.source, "constructor");
    }

    /// End-to-end (Lua): a colon-method call `proc:initialize()` resolves to the
    /// enclosing table's type via the shared `apply_type_resolution` path, and
    /// two same-named methods on different tables are NOT conflated.
    #[test]
    fn test_lua_colon_method_receiver_type_not_conflated() {
        use crate::callgraph::languages::CallGraphLanguageSupport;
        use crate::callgraph::resolution::apply_type_resolution;

        let source = r#"
function Process:initialize()
  return true
end

function Widget:initialize()
  return true
end

local proc = Process.new()
local widget = Widget.new()

local function run()
  proc:initialize()
  widget:initialize()
end
"#;
        let handler = crate::callgraph::languages::LuaHandler::new();
        let path = std::path::Path::new("m.lua");
        let tree = parse_source(source, "lua").unwrap();
        let calls = handler.extract_calls(path, source, &tree).unwrap();
        let (funcs, classes) = handler.extract_definitions(source, path, &tree).unwrap();

        let mut file_ir = crate::callgraph::cross_file_types::FileIR::new(path.to_path_buf());
        file_ir.funcs = funcs;
        file_ir.classes = classes;
        file_ir.var_types = extract_lua_var_types(&tree, source.as_bytes());
        file_ir.calls = calls;

        apply_type_resolution(&mut file_ir, source, crate::types::Language::Lua);

        let run_calls = file_ir.calls.get("run").expect("run caller present");
        let proc_call = run_calls
            .iter()
            .find(|c| c.target == "proc:initialize")
            .expect("proc:initialize call present");
        let widget_call = run_calls
            .iter()
            .find(|c| c.target == "widget:initialize")
            .expect("widget:initialize call present");

        assert_eq!(
            proc_call.receiver_type.as_deref(),
            Some("Process"),
            "proc:initialize receiver must be typed Process (d.4 supplies it)"
        );
        assert_eq!(
            widget_call.receiver_type.as_deref(),
            Some("Widget"),
            "widget:initialize receiver must be typed Widget"
        );
        assert_ne!(
            proc_call.receiver_type, widget_call.receiver_type,
            "same-named colon methods on different tables must NOT be conflated"
        );
    }

    /// End-to-end (Luau): a cross-module `inst:setState()` where
    /// `inst = Component.new()` (setState defined in the required Component
    /// module, NOT locally) keeps its `Method` classification and has its
    /// receiver typed to `Component` through the shared resolution path.
    ///
    /// NOTE: when the colon-method name IS defined in the same file, the luau
    /// CALL handler collapses `obj:method()` to `CallType::Intra` and drops the
    /// receiver (luau.rs) — a d.2/d.3 call-extraction concern, orthogonal to the
    /// d.4 receiver-type SUPPLY exercised here.
    #[test]
    fn test_luau_colon_method_receiver_type_filled() {
        use crate::callgraph::languages::CallGraphLanguageSupport;
        use crate::callgraph::resolution::apply_type_resolution;

        let source = r#"
local Component = require(script.Component)

local function build()
  local inst = Component.new()
  inst:setState()
end
"#;
        let handler = crate::callgraph::languages::LuauHandler::new();
        let path = std::path::Path::new("c.luau");
        let tree = parse_source(source, "luau").unwrap();
        let calls = handler.extract_calls(path, source, &tree).unwrap();
        let (funcs, classes) = handler.extract_definitions(source, path, &tree).unwrap();

        // The luau var_types extractor supplies `inst : Component` (RTA factory).
        let var_types = extract_luau_var_types(&tree, source.as_bytes());
        let inst_vt = var_types
            .iter()
            .find(|v| v.var_name == "inst")
            .expect("inst should be typed by Component.new()");
        assert_eq!(inst_vt.type_name, "Component");
        assert_eq!(inst_vt.source, "constructor");
        assert_eq!(inst_vt.scope, Some("build".to_string()));

        let mut file_ir = crate::callgraph::cross_file_types::FileIR::new(path.to_path_buf());
        file_ir.funcs = funcs;
        file_ir.classes = classes;
        file_ir.var_types = var_types;
        file_ir.calls = calls;

        apply_type_resolution(&mut file_ir, source, crate::types::Language::Luau);

        let build_calls = file_ir.calls.get("build").expect("build caller present");
        let set_state = build_calls
            .iter()
            .find(|c| c.target == "inst:setState")
            .expect("inst:setState call present as a Method");
        assert_eq!(
            set_state.receiver_type.as_deref(),
            Some("Component"),
            "inst:setState receiver must be typed Component (d.4 supplies it)"
        );
    }

    // =====================================================================
    // FEATURE-1 d.5 (Part A): declared-return-type propagation.
    //
    // Pattern under test: `x = make(); x.method()` where `make()` has a declared
    // return type `T` and `method` is NOT defined in the same file (so the call
    // graph keeps `x.method()` as a Method/Attr call whose receiver can be typed
    // — the same shape the d.4 luau `setState` test uses). We assert:
    //   1. the return-derived VarType for `x` has `source == "return"` (Medium),
    //   2. after `apply_type_resolution` the `x.method()` receiver is typed `T`.
    // =====================================================================

    /// Shared assertion: `x`'s VarType is return-derived (Medium) and the
    /// `x.method()` call site is typed `expected`.
    fn assert_return_prop(
        lang: crate::types::Language,
        var_types: Vec<VarType>,
        calls: HashMap<String, Vec<CallSite>>,
        funcs: Vec<FuncDef>,
        classes: Vec<ClassDef>,
        path: &std::path::Path,
        source: &str,
        expected: &str,
    ) {
        use crate::callgraph::resolution::apply_type_resolution;

        let x_vt = var_types
            .iter()
            .find(|v| v.var_name == "x")
            .unwrap_or_else(|| panic!("[{:?}] expected a VarType for x", lang));
        assert_eq!(
            x_vt.type_name, expected,
            "[{:?}] x should be typed {} from the return type",
            lang, expected
        );
        assert_eq!(
            x_vt.source, "return",
            "[{:?}] return-derived VarType must carry source=\"return\" (Medium)",
            lang
        );

        let mut file_ir = crate::callgraph::cross_file_types::FileIR::new(path.to_path_buf());
        file_ir.funcs = funcs;
        file_ir.classes = classes;
        file_ir.var_types = var_types;
        file_ir.calls = calls;
        apply_type_resolution(&mut file_ir, source, lang);

        // Locate the `x.method()` call by receiver (target spelling varies per
        // language: Go keeps "x.Render", Kotlin stores method="render" + receiver).
        // Some handlers store the caller under BOTH a simple and a qualified key
        // (e.g. C# "Run" and "Factory.Run"); the return-derived scope matches the
        // qualified caller, so assert that AT LEAST ONE receiver-x call is typed.
        let x_calls: Vec<Option<String>> = file_ir
            .calls
            .values()
            .flat_map(|cs| cs.iter())
            .filter(|c| c.receiver.as_deref() == Some("x"))
            .map(|c| c.receiver_type.clone())
            .collect();
        assert!(
            !x_calls.is_empty(),
            "[{:?}] no call with receiver x found",
            lang
        );
        assert!(
            x_calls.iter().any(|t| t.as_deref() == Some(expected)),
            "[{:?}] x.method receiver must be typed {} via return-prop (were {:?})",
            lang,
            expected,
            x_calls
        );
    }

    #[test]
    fn test_d5_return_prop_go() {
        use crate::callgraph::languages::CallGraphLanguageSupport;
        let source = r#"
package main

type Widget struct{}

func makeWidget() *Widget {
    return &Widget{}
}

func run() {
    x := makeWidget()
    x.Render()
}
"#;
        let handler = crate::callgraph::languages::GoHandler::new();
        let path = std::path::Path::new("m.go");
        let tree = parse_source(source, "go").unwrap();
        let calls = handler.extract_calls(path, source, &tree).unwrap();
        let (funcs, classes) = handler.extract_definitions(source, path, &tree).unwrap();
        let vts = extract_go_var_types(&tree, source.as_bytes());
        assert_return_prop(
            crate::types::Language::Go,
            vts,
            calls,
            funcs,
            classes,
            path,
            source,

            "Widget",
        );
    }

    #[test]
    fn test_d5_return_prop_rust() {
        use crate::callgraph::languages::CallGraphLanguageSupport;
        let source = r#"
struct Widget;

fn make_widget() -> Widget {
    Widget
}

fn run() {
    let x = make_widget();
    x.render();
}
"#;
        let handler = crate::callgraph::languages::RustLangHandler::new();
        let path = std::path::Path::new("m.rs");
        let tree = parse_source(source, "rust").unwrap();
        let calls = handler.extract_calls(path, source, &tree).unwrap();
        let (funcs, classes) = handler.extract_definitions(source, path, &tree).unwrap();
        let vts = extract_rust_var_types(&tree, source.as_bytes());
        assert_return_prop(
            crate::types::Language::Rust,
            vts,
            calls,
            funcs,
            classes,
            path,
            source,

            "Widget",
        );
    }

    #[test]
    fn test_d5_return_prop_typescript() {
        use crate::callgraph::languages::CallGraphLanguageSupport;
        let source = r#"
function makeWidget(): Widget {
    return new Widget();
}

function run() {
    const x = makeWidget();
    x.render();
}
"#;
        let handler = crate::callgraph::languages::TypeScriptHandler::new();
        let path = std::path::Path::new("m.ts");
        let tree = parse_source(source, "typescript").unwrap();
        let calls = handler.extract_calls(path, source, &tree).unwrap();
        let (funcs, classes) = handler.extract_definitions(source, path, &tree).unwrap();
        let vts = extract_ts_var_types(&tree, source.as_bytes());
        assert_return_prop(
            crate::types::Language::TypeScript,
            vts,
            calls,
            funcs,
            classes,
            path,
            source,

            "Widget",
        );
    }

    #[test]
    fn test_d5_return_prop_java() {
        use crate::callgraph::languages::CallGraphLanguageSupport;
        let source = r#"
class Factory {
    Widget makeWidget() {
        return null;
    }

    void run() {
        var x = makeWidget();
        x.render();
    }
}
"#;
        let handler = crate::callgraph::languages::JavaHandler::new();
        let path = std::path::Path::new("M.java");
        let tree = parse_source(source, "java").unwrap();
        let calls = handler.extract_calls(path, source, &tree).unwrap();
        let (funcs, classes) = handler.extract_definitions(source, path, &tree).unwrap();
        let vts = extract_java_var_types(&tree, source.as_bytes());
        assert_return_prop(
            crate::types::Language::Java,
            vts,
            calls,
            funcs,
            classes,
            path,
            source,

            "Widget",
        );
    }

    #[test]
    fn test_d5_return_prop_kotlin() {
        use crate::callgraph::languages::CallGraphLanguageSupport;
        let source = r#"
fun makeWidget(): Widget {
    return Widget()
}

fun run() {
    val x = makeWidget()
    x.render()
}
"#;
        let handler = crate::callgraph::languages::KotlinHandler::new();
        let path = std::path::Path::new("m.kt");
        let tree = parse_source(source, "kotlin").unwrap();
        let calls = handler.extract_calls(path, source, &tree).unwrap();
        let (funcs, classes) = handler.extract_definitions(source, path, &tree).unwrap();
        let vts = extract_kotlin_var_types(&tree, source.as_bytes());
        assert_return_prop(
            crate::types::Language::Kotlin,
            vts,
            calls,
            funcs,
            classes,
            path,
            source,

            "Widget",
        );
    }

    /// Dynamic-language ceiling: Python has no declared return types, so
    /// `x = make(); x.render()` leaves `x` untyped. This is CORRECT (ceiling),
    /// not a gap: no return-derived VarType is produced.
    #[test]
    fn test_d5_return_prop_python_ceiling_untyped() {
        let source = r#"
def make_widget():
    return Widget()

def run():
    x = make_widget()
    x.render()
"#;
        let tree = parse_source(source, "python").unwrap();
        let vts = extract_python_var_types(&tree, source.as_bytes());
        assert!(
            vts.iter().all(|v| !(v.var_name == "x" && v.source == "return")),
            "python has no declared return types; x must stay untyped (ceiling)"
        );
    }

    // =====================================================================
    // FEATURE-1 d.5 (Part B): Lua/Luau self-chain scope-key reconciliation.
    //
    // `function T:m() self:other() end` — the d.4 self VarType is scoped by the
    // qualified method name ("T:m") while the (luau) caller key is the simple
    // method name ("m"). The find_best_vartype method-component fallback now
    // consumes it so `self` resolves to the enclosing table `T`. `other` is left
    // undefined here so the call keeps its Method classification (a locally
    // defined colon-method collapses to Intra in luau and drops the receiver).
    // =====================================================================

    #[test]
    fn test_d5_self_chain_luau() {
        use crate::callgraph::languages::CallGraphLanguageSupport;
        use crate::callgraph::resolution::apply_type_resolution;

        let source = r#"
function T:m()
  self:other()
end
"#;
        let handler = crate::callgraph::languages::LuauHandler::new();
        let path = std::path::Path::new("m.luau");
        let tree = parse_source(source, "luau").unwrap();
        let calls = handler.extract_calls(path, source, &tree).unwrap();
        let (funcs, classes) = handler.extract_definitions(source, path, &tree).unwrap();
        let var_types = extract_luau_var_types(&tree, source.as_bytes());

        // d.4 supplies the self VarType scoped by the qualified method name.
        let self_vt = var_types
            .iter()
            .find(|v| v.var_name == "self")
            .expect("luau self VarType supplied by collect_lua_self_receiver");
        assert_eq!(self_vt.type_name, "T");
        assert_eq!(self_vt.scope.as_deref(), Some("T:m"));

        let mut file_ir = crate::callgraph::cross_file_types::FileIR::new(path.to_path_buf());
        file_ir.funcs = funcs;
        file_ir.classes = classes;
        file_ir.var_types = var_types;
        file_ir.calls = calls;
        apply_type_resolution(&mut file_ir, source, crate::types::Language::Luau);

        let m_calls = file_ir.calls.get("m").expect("caller m present");
        let self_other = m_calls
            .iter()
            .find(|c| c.target == "self:other")
            .expect("self:other kept as a Method call");
        assert_eq!(
            self_other.receiver_type.as_deref(),
            Some("T"),
            "d.5 must reconcile the scope key so self resolves to enclosing table T"
        );
    }

    #[test]
    fn test_d5_return_prop_csharp() {
        use crate::callgraph::languages::CallGraphLanguageSupport;
        let source = r#"
class Factory {
    Widget MakeWidget() { return null; }
    void Run() {
        var x = MakeWidget();
        x.Render();
    }
}
"#;
        let handler = crate::callgraph::languages::CsharpHandler::new();
        let path = std::path::Path::new("m.cs");
        let tree = parse_source(source, "csharp").unwrap();
        let calls = handler.extract_calls(path, source, &tree).unwrap();
        let (funcs, classes) = handler.extract_definitions(source, path, &tree).unwrap();
        let vts = extract_csharp_var_types(&tree, source.as_bytes());
        assert_return_prop(
            crate::types::Language::CSharp,
            vts,
            calls,
            funcs,
            classes,
            path,
            source,
            "Widget",
        );
    }

    #[test]
    fn test_d5_return_prop_swift() {
        use crate::callgraph::languages::CallGraphLanguageSupport;
        let source = r#"
func makeWidget() -> Widget {
    return Widget()
}
func run() {
    let x = makeWidget()
    x.render()
}
"#;
        let handler = crate::callgraph::languages::SwiftHandler::new();
        let path = std::path::Path::new("m.swift");
        let tree = parse_source(source, "swift").unwrap();
        let calls = handler.extract_calls(path, source, &tree).unwrap();
        let (funcs, classes) = handler.extract_definitions(source, path, &tree).unwrap();
        let vts = extract_swift_var_types(&tree, source.as_bytes());
        assert_return_prop(
            crate::types::Language::Swift,
            vts,
            calls,
            funcs,
            classes,
            path,
            source,
            "Widget",
        );
    }

    #[test]
    fn test_d5_self_chain_lua() {
        use crate::callgraph::languages::CallGraphLanguageSupport;
        use crate::callgraph::resolution::apply_type_resolution;

        let source = r#"
function T:m()
  self:other()
end
"#;
        let handler = crate::callgraph::languages::LuaHandler::new();
        let path = std::path::Path::new("m.lua");
        let tree = parse_source(source, "lua").unwrap();
        let calls = handler.extract_calls(path, source, &tree).unwrap();
        let (funcs, classes) = handler.extract_definitions(source, path, &tree).unwrap();
        let var_types = extract_lua_var_types(&tree, source.as_bytes());

        let mut file_ir = crate::callgraph::cross_file_types::FileIR::new(path.to_path_buf());
        file_ir.funcs = funcs;
        file_ir.classes = classes;
        file_ir.var_types = var_types;
        file_ir.calls = calls;
        apply_type_resolution(&mut file_ir, source, crate::types::Language::Lua);

        // Lua stores the caller under BOTH the qualified ("T:m") and simple ("m")
        // keys. After d.5 the simple-key entry resolves self->T too (the qualified
        // key already matched via exact scope). Both must be consistent.
        let m_calls = file_ir.calls.get("m").expect("simple caller key m present");
        let self_other = m_calls
            .iter()
            .find(|c| c.target == "self:other")
            .expect("self:other kept as a Method call under simple key");
        assert_eq!(
            self_other.receiver_type.as_deref(),
            Some("T"),
            "d.5 method-component fallback must type self as T under the simple caller key"
        );
    }
}
