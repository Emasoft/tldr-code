//! Explain Command - Comprehensive Function Analysis
//!
//! The explain command provides a complete analysis of a function including:
//! - Signature extraction (params, return type, decorators, docstring)
//! - Purity analysis (pure/impure/unknown with effects)
//! - Complexity metrics (cyclomatic, blocks, edges, loops)
//! - Call relationships (callers and callees)
//!
//! # Example
//!
//! ```bash
//! # Analyze a function
//! tldr explain src/utils.py calculate_total
//!
//! # With call graph depth
//! tldr explain src/utils.py calculate_total --depth 3
//!
//! # Text output
//! tldr explain src/utils.py calculate_total --format text
//! ```

use std::collections::HashSet;
use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use tree_sitter::{Node, Parser};

use super::error::RemainingError;
use super::types::{CallInfo, ComplexityInfo, ExplainReport, ParamInfo, PurityInfo, SignatureInfo};

use crate::output::{OutputFormat, OutputWriter};
use tldr_core::ast::extract::decl_keyword_line_from_node;
use tldr_core::types::Language;
use tldr_core::{
    build_project_call_graph, find_references, impact_analysis_with_ast_fallback, names_match,
    ReferenceKind, ReferencesOptions,
};

// =============================================================================
// CLI Arguments
// =============================================================================

/// Provide comprehensive function analysis.
#[derive(Debug, Clone, Args)]
pub struct ExplainArgs {
    /// Source file to analyze
    pub file: PathBuf,

    /// Function name to explain
    pub function: String,

    /// Call graph depth for callers/callees
    #[arg(long, default_value = "2")]
    pub depth: u32,

    /// Output file (stdout if not specified)
    #[arg(long, short = 'o')]
    pub output: Option<PathBuf>,
}

// =============================================================================
// Constants
// =============================================================================

/// Known I/O operations that make a function impure
const IO_OPERATIONS: &[&str] = &[
    "print",
    "open",
    "read",
    "write",
    "readline",
    "readlines",
    "writelines",
    "input",
    "system",
    "popen",
    "exec",
    "eval",
    "request",
    "fetch",
    "urlopen",
    "execute",
    "executemany",
    "fetchone",
    "fetchall",
];

/// Known impure calls (non-deterministic or side-effecting)
const IMPURE_CALLS: &[&str] = &[
    "random",
    "randint",
    "choice",
    "shuffle",
    "sample",
    "uniform",
    "random.random",
    "random.randint",
    "random.choice",
    "random.shuffle",
    "time",
    "time.time",
    "datetime.now",
    "datetime.datetime.now",
    "uuid4",
    "uuid1",
    "uuid.uuid4",
    "uuid.uuid1",
    "logging.info",
    "logging.debug",
    "logging.warning",
    "logging.error",
    "os.system",
    "os.popen",
    "os.getenv",
    "os.environ",
    "os.mkdir",
    "os.remove",
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.delete",
    "subprocess.run",
    "subprocess.call",
    "subprocess.Popen",
];

/// Collection mutation methods
const COLLECTION_MUTATIONS: &[&str] = &[
    "append",
    "extend",
    "insert",
    "remove",
    "pop",
    "clear",
    "update",
    "add",
    "discard",
    "setdefault",
    "sort",
    "reverse",
];

/// Known pure builtins
const PURE_BUILTINS: &[&str] = &[
    "len",
    "range",
    "int",
    "float",
    "str",
    "bool",
    "list",
    "dict",
    "set",
    "tuple",
    "sorted",
    "reversed",
    "enumerate",
    "zip",
    "map",
    "filter",
    "min",
    "max",
    "sum",
    "abs",
    "round",
    "isinstance",
    "issubclass",
    "type",
    "id",
    "hash",
    "repr",
    "next",
    "iter",
    "all",
    "any",
    "chr",
    "ord",
    "hex",
    "oct",
    "bin",
    "pow",
    "divmod",
    "super",
    "property",
    "staticmethod",
    "classmethod",
];

// =============================================================================
// Tree-sitter Multi-Language Parsing
// =============================================================================

/// Get function node kinds for a given language
fn get_function_node_kinds(language: Language) -> &'static [&'static str] {
    match language {
        Language::Python => &["function_definition", "async_function_definition"],
        Language::TypeScript | Language::JavaScript => &[
            "function_declaration",
            "arrow_function",
            "method_definition",
            "function",
        ],
        Language::Go => &["function_declaration", "method_declaration"],
        Language::Rust => &["function_item"],
        Language::Java => &["method_declaration", "constructor_declaration"],
        Language::Kotlin => &["function_declaration"],
        Language::CSharp => &["method_declaration", "constructor_declaration"],
        Language::Ruby => &["method", "singleton_method"],
        Language::Php => &["function_definition", "method_declaration"],
        Language::Scala => &["function_definition"],
        Language::Swift => &["function_declaration"],
        Language::C | Language::Cpp => &["function_definition"],
        Language::Lua | Language::Luau => &["function_declaration", "function_definition"],
        Language::Elixir => &["call"], // Elixir def/defp are call nodes
        Language::Ocaml => &["value_definition"],
    }
}

/// Initialize tree-sitter parser for the detected language
fn get_parser(language: Language) -> Result<Parser, RemainingError> {
    let mut parser = Parser::new();

    let ts_language = match language {
        Language::Python => tree_sitter_python::LANGUAGE.into(),
        Language::TypeScript => tree_sitter_typescript::LANGUAGE_TSX.into(),
        Language::JavaScript => tree_sitter_typescript::LANGUAGE_TSX.into(),
        Language::Go => tree_sitter_go::LANGUAGE.into(),
        Language::Rust => tree_sitter_rust::LANGUAGE.into(),
        Language::Java => tree_sitter_java::LANGUAGE.into(),
        Language::C => tree_sitter_c::LANGUAGE.into(),
        Language::Cpp => tree_sitter_cpp::LANGUAGE.into(),
        Language::CSharp => tree_sitter_c_sharp::LANGUAGE.into(),
        Language::Kotlin => tree_sitter_kotlin_ng::LANGUAGE.into(),
        Language::Scala => tree_sitter_scala::LANGUAGE.into(),
        Language::Php => tree_sitter_php::LANGUAGE_PHP.into(),
        Language::Ruby => tree_sitter_ruby::LANGUAGE.into(),
        Language::Lua => tree_sitter_lua::LANGUAGE.into(),
        Language::Luau => tree_sitter_luau::LANGUAGE.into(),
        Language::Elixir => tree_sitter_elixir::LANGUAGE.into(),
        Language::Ocaml => tree_sitter_ocaml::LANGUAGE_OCAML.into(),
        Language::Swift => tree_sitter_swift::LANGUAGE.into(),
    };

    parser.set_language(&ts_language).map_err(|e| {
        RemainingError::parse_error(PathBuf::new(), format!("Failed to set language: {}", e))
    })?;
    Ok(parser)
}

/// Get text for a node from source
fn node_text<'a>(node: Node, source: &'a [u8]) -> &'a str {
    node.utf8_text(source).unwrap_or("")
}

/// Get the line number (1-indexed) for a node
fn get_line_number(node: Node) -> u32 {
    node.start_position().row as u32 + 1
}

/// Get the end line number (1-indexed) for a node
fn get_end_line_number(node: Node) -> u32 {
    node.end_position().row as u32 + 1
}

// =============================================================================
// Function Finding
// =============================================================================

/// Find a function definition by name in the AST.
///
/// Accepts either a bare function name (`run`) or a qualified
/// `Class.method` form (`Flask.run`). When a qualified name is given:
///   1. The class is located via [`find_class_node_explain`].
///   2. The method is searched within the class subtree.
///   3. If the class is not found OR the method is not found inside it,
///      falls back to the LAST component as a bare name.
fn find_function_node<'a>(
    root: Node<'a>,
    source: &[u8],
    function_name: &str,
    func_kinds: &[&str],
) -> Option<Node<'a>> {
    if function_name.contains('.') {
        let parts: Vec<&str> = function_name.split('.').collect();
        if parts.len() >= 2 {
            let class_name = parts[0];
            let remainder = parts[1..].join(".");
            if let Some(class_node) = find_class_node_explain(root, class_name, source) {
                let scope = class_node
                    .child_by_field_name("body")
                    .unwrap_or(class_node);
                if let Some(found) =
                    find_function_recursive(scope, source, &remainder, func_kinds)
                {
                    return Some(found);
                }
            }
            // Fallback: try the LAST component as a bare name.
            let last = *parts.last().unwrap();
            return find_function_recursive(root, source, last, func_kinds);
        }
    }
    find_function_recursive(root, source, function_name, func_kinds)
}

/// Locate a class/struct/trait/interface container by name. Used to
/// scope `Class.method` lookups in [`find_function_node`]. The set of
/// container kinds intentionally covers all major OO/struct grammars
/// supported by tldr.
fn find_class_node_explain<'a>(
    root: Node<'a>,
    class_name: &str,
    source: &[u8],
) -> Option<Node<'a>> {
    const CLASS_KINDS: &[&str] = &[
        // Python
        "class_definition",
        // TS/JS/Java/PHP/C#/Kotlin/Swift/Ruby
        "class_declaration",
        "class",
        "interface_declaration",
        // Rust
        "struct_item",
        "enum_item",
        "trait_item",
        "impl_item",
        "union_item",
        // C++
        "class_specifier",
        "struct_specifier",
        "union_specifier",
        // Java
        "enum_declaration",
        "record_declaration",
        // PHP
        "trait_declaration",
        // C#
        "struct_declaration",
        // Kotlin / Scala
        "object_declaration",
        "class_definition",
        "object_definition",
        "trait_definition",
        // Swift
        "protocol_declaration",
        "extension_declaration",
        // Ruby
        "module",
    ];

    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if CLASS_KINDS.contains(&node.kind()) {
            // Try the conventional "name" field first.
            let name_match = node.child_by_field_name("name").is_some_and(|n| {
                node_text(n, source) == class_name
            });
            if name_match {
                return Some(node);
            }
            // Fallback: scan named children for an identifier-shaped name
            // (Rust struct/enum/trait/impl, C++ class_specifier).
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if matches!(
                    child.kind(),
                    "identifier" | "type_identifier" | "constant"
                ) {
                    if node_text(child, source) == class_name {
                        return Some(node);
                    }
                    break;
                }
            }
        }
        let mut cursor = node.walk();
        let children: Vec<_> = node.children(&mut cursor).collect();
        for child in children.into_iter().rev() {
            stack.push(child);
        }
    }
    None
}

fn find_function_recursive<'a>(
    node: Node<'a>,
    source: &[u8],
    function_name: &str,
    func_kinds: &[&str],
) -> Option<Node<'a>> {
    if func_kinds.contains(&node.kind()) {
        // Check if this function has the name we're looking for
        // Try field name first (most reliable)
        if let Some(name_node) = node.child_by_field_name("name") {
            let name = node_text(name_node, source);
            if name == function_name {
                return Some(node);
            }
        }
        // C/C++: function_definition -> declarator -> function_declarator -> identifier
        if let Some(declarator) = node.child_by_field_name("declarator") {
            if let Some(name) = extract_c_declarator_name_explain(declarator, source) {
                if name == function_name {
                    return Some(node);
                }
            }
        }
        // Fallback: search for identifier child (Python, etc.)
        for child in node.children(&mut node.walk()) {
            if child.kind() == "identifier" {
                let name = node_text(child, source);
                if name == function_name {
                    return Some(node);
                }
                break;
            }
        }
    }

    // Check for arrow functions in variable declarations (TS/JS pattern):
    // lexical_declaration / variable_declaration -> variable_declarator -> name + value(arrow_function)
    if matches!(node.kind(), "lexical_declaration" | "variable_declaration") {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "variable_declarator" {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let var_name = node_text(name_node, source);
                    if var_name == function_name {
                        if let Some(value_node) = child.child_by_field_name("value") {
                            if matches!(
                                value_node.kind(),
                                "arrow_function"
                                    | "function"
                                    | "function_expression"
                                    | "generator_function"
                            ) {
                                return Some(value_node);
                            }
                        }
                    }
                }
            }
        }
    }

    // (js-extract-function-expressions-v1) JS/TS function-expression assignments:
    //   app.use = function() {}
    //   Foo.prototype.bar = function() {}
    //   handler = () => {}
    if node.kind() == "assignment_expression" {
        if let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) {
            let target_name = match left.kind() {
                "identifier" => Some(node_text(left, source).to_string()),
                "member_expression" => left
                    .child_by_field_name("property")
                    .map(|p| node_text(p, source).to_string()),
                _ => None,
            };
            if let Some(name) = target_name {
                if name == function_name
                    && matches!(
                        right.kind(),
                        "arrow_function"
                            | "function"
                            | "function_expression"
                            | "generator_function"
                    )
                {
                    return Some(right);
                }
            }
        }
    }

    // (js-extract-function-expressions-v1) Object literal pair:
    //   { foo: function() {} }  /  { foo: () => {} }
    if node.kind() == "pair" {
        if let (Some(key), Some(value)) = (
            node.child_by_field_name("key"),
            node.child_by_field_name("value"),
        ) {
            let key_name = match key.kind() {
                "property_identifier" | "identifier" => node_text(key, source).to_string(),
                "string" => node_text(key, source)
                    .trim_matches(|c| c == '"' || c == '\'' || c == '`')
                    .to_string(),
                _ => String::new(),
            };
            if key_name == function_name
                && matches!(
                    value.kind(),
                    "arrow_function"
                        | "function"
                        | "function_expression"
                        | "generator_function"
                )
            {
                return Some(value);
            }
        }
    }

    // Elixir: def/defp are `call` nodes where the first child identifier is "def"/"defp"
    // and the function name is in the arguments
    if node.kind() == "call" && func_kinds.contains(&"call") {
        for child in node.children(&mut node.walk()) {
            if child.kind() == "identifier" {
                let text = node_text(child, source);
                if text == "def" || text == "defp" {
                    if let Some(args) = child.next_sibling() {
                        if args.kind() == "arguments" || args.kind() == "call" {
                            if let Some(name_node) = args.child(0) {
                                let fname = if name_node.kind() == "call" {
                                    name_node
                                        .child(0)
                                        .map(|n| node_text(n, source))
                                        .unwrap_or("")
                                } else {
                                    node_text(name_node, source)
                                };
                                if fname == function_name {
                                    return Some(node);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // OCaml: value_definition -> let_binding -> pattern field contains the function name
    if node.kind() == "value_definition" {
        for child in node.children(&mut node.walk()) {
            if child.kind() == "let_binding" {
                if let Some(pattern_node) = child.child_by_field_name("pattern") {
                    let name = node_text(pattern_node, source);
                    if name == function_name {
                        return Some(node);
                    }
                }
            }
        }
    }

    // Recurse into children
    for child in node.children(&mut node.walk()) {
        if let Some(found) = find_function_recursive(child, source, function_name, func_kinds) {
            return Some(found);
        }
    }

    None
}

/// Recursively extract function name from C/C++ nested declarator chain
fn extract_c_declarator_name_explain(declarator: Node, source: &[u8]) -> Option<String> {
    match declarator.kind() {
        "identifier" | "field_identifier" => {
            let name = node_text(declarator, source).to_string();
            if !name.is_empty() {
                Some(name)
            } else {
                None
            }
        }
        "function_declarator"
        | "pointer_declarator"
        | "reference_declarator"
        | "parenthesized_declarator" => declarator
            .child_by_field_name("declarator")
            .and_then(|inner| extract_c_declarator_name_explain(inner, source)),
        _ => None,
    }
}

// =============================================================================
// Signature Extraction
// =============================================================================

/// Extract signature information from a function node
fn extract_signature(func_node: Node, source: &[u8], language: Language) -> SignatureInfo {
    let mut sig = SignatureInfo::new();

    // Check if async (language-specific)
    sig.is_async = match language {
        Language::Python => func_node.kind() == "async_function_definition",
        Language::TypeScript | Language::JavaScript => {
            // Check for async modifier
            let mut is_async = false;
            for child in func_node.children(&mut func_node.walk()) {
                if child.kind() == "async" {
                    is_async = true;
                    break;
                }
            }
            is_async
        }
        Language::Rust => {
            // Check for async keyword
            node_text(func_node, source).contains("async")
        }
        _ => false,
    };

    // Extract parameters
    if let Some(params_node) = func_node.child_by_field_name("parameters") {
        sig.params = extract_params(params_node, source);
    } else if matches!(language, Language::Kotlin) {
        // Kotlin's tree-sitter grammar exposes the parameter list as a
        // NAMED child `function_value_parameters` rather than a field, so
        // `child_by_field_name("parameters")` silently misses it. Walk the
        // children directly. (kotlin-extract-params-v1 / VAL-KT-EXTRACT)
        if let Some(params_node) = func_node
            .children(&mut func_node.walk())
            .find(|c| c.kind() == "function_value_parameters")
        {
            sig.params = extract_kotlin_params(params_node, source);
        }
    }

    // explain-signature-params-v1 (v0.4.2 M-001): if the legacy generic
    // walker above returned no params, fall back to the canonical
    // language-aware dispatcher from `tldr_core::ast::extract`. This is
    // the same code path that `tldr extract` uses to populate
    // `functions[].params`, so explain.signature.params now matches
    // extract.params for the 15 langs whose tree-sitter grammar does not
    // expose a `parameters` field with python-style children
    // (rust, java, javascript/typescript, go, c, cpp, csharp, scala,
    // swift, ruby, php, lua, luau, ocaml, elixir).
    //
    // The dispatcher returns `Vec<String>` of name fragments; we wrap each
    // entry in a `ParamInfo` (name-only) so the existing schema
    // `signature.params[].{name,type?,default?}` is preserved. Type and
    // default fields are intentionally absent on the fallback path because
    // the language-specific extractors in tldr-core only emit names
    // today — extending them to typed entries is a follow-up. Python's
    // generic walker still runs first, so the rich typed entries python
    // already emits are not regressed.
    if sig.params.is_empty() {
        let source_str = std::str::from_utf8(source).unwrap_or("");
        let fallback = tldr_core::ast::extract_function_params(&func_node, source_str, language);
        if !fallback.is_empty() {
            sig.params = fallback
                .into_iter()
                .filter(|n| !n.is_empty())
                .map(ParamInfo::new)
                .collect();
        }
    }

    // Extract return type
    if let Some(return_node) = func_node.child_by_field_name("return_type") {
        sig.return_type = Some(node_text(return_node, source).to_string());
    }

    // Extract decorators (look for decorated_definition parent or decorator children)
    sig.decorators = extract_decorators(func_node, source);

    // Extract docstring
    sig.docstring = extract_docstring(func_node, source);

    sig
}

/// Extract kotlin parameters from a `function_value_parameters` node.
///
/// Each `parameter` child has shape `identifier ":" <type>` under the
/// tree-sitter-kotlin-ng 1.1.0 grammar. Older grammars used
/// `simple_identifier` for the name; both are accepted for back-compat.
fn extract_kotlin_params(params_node: Node, source: &[u8]) -> Vec<ParamInfo> {
    let mut params = Vec::new();

    for child in params_node.children(&mut params_node.walk()) {
        // The wrapper may be `parameter` (current) or
        // `function_value_parameter` (legacy grammars).
        let inner = match child.kind() {
            "parameter" => Some(child),
            "function_value_parameter" => child
                .child_by_field_name("parameter")
                .or(Some(child)),
            _ => None,
        };
        let Some(param_node) = inner else { continue };

        let mut name: Option<String> = None;
        let mut type_hint: Option<String> = None;
        let mut saw_colon = false;

        for part in param_node.children(&mut param_node.walk()) {
            match part.kind() {
                "simple_identifier" | "identifier" if name.is_none() => {
                    name = Some(node_text(part, source).to_string());
                }
                ":" => {
                    saw_colon = true;
                }
                _ if saw_colon && type_hint.is_none() => {
                    // First non-trivial node after the colon is the type.
                    let txt = node_text(part, source);
                    if !txt.is_empty() && part.kind() != "=" {
                        type_hint = Some(txt.to_string());
                    }
                }
                _ => {}
            }
        }

        if let Some(n) = name {
            let mut p = ParamInfo::new(n);
            if let Some(t) = type_hint {
                p = p.with_type(t);
            }
            params.push(p);
        }
    }

    params
}

/// Extract parameters from a parameters node
fn extract_params(params_node: Node, source: &[u8]) -> Vec<ParamInfo> {
    let mut params = Vec::new();

    for child in params_node.children(&mut params_node.walk()) {
        match child.kind() {
            "identifier" => {
                // Simple parameter without annotation
                let name = node_text(child, source);
                if name != "self" && name != "cls" {
                    params.push(ParamInfo::new(name));
                }
            }
            "typed_parameter" | "typed_default_parameter" => {
                // Parameter with type annotation
                let mut param = ParamInfo::new("");
                for part in child.children(&mut child.walk()) {
                    match part.kind() {
                        "identifier" => {
                            let name = node_text(part, source);
                            if name != "self" && name != "cls" && param.name.is_empty() {
                                param.name = name.to_string();
                            }
                        }
                        "type" => {
                            param.type_hint = Some(node_text(part, source).to_string());
                        }
                        _ => {}
                    }
                }
                // Only add if we got a name
                if !param.name.is_empty() {
                    params.push(param);
                }
            }
            "default_parameter" => {
                // Parameter with default value
                let mut param = ParamInfo::new("");
                let mut got_name = false;
                for part in child.children(&mut child.walk()) {
                    if part.kind() == "identifier" && !got_name {
                        let name = node_text(part, source);
                        if name != "self" && name != "cls" {
                            param.name = name.to_string();
                            got_name = true;
                        }
                    } else if got_name && param.default.is_none() && part.kind() != "=" {
                        param.default = Some(node_text(part, source).to_string());
                    }
                }
                if !param.name.is_empty() {
                    params.push(param);
                }
            }
            _ => {}
        }
    }

    params
}

/// Extract decorators
fn extract_decorators(func_node: Node, source: &[u8]) -> Vec<String> {
    let mut decorators = Vec::new();

    // Check if parent is decorated_definition
    if let Some(parent) = func_node.parent() {
        if parent.kind() == "decorated_definition" {
            for child in parent.children(&mut parent.walk()) {
                if child.kind() == "decorator" {
                    let text = node_text(child, source);
                    decorators.push(text.trim_start_matches('@').to_string());
                }
            }
        }
    }

    decorators
}

/// Extract docstring from function body
fn extract_docstring(func_node: Node, source: &[u8]) -> Option<String> {
    // Look for the function body (block)
    if let Some(body) = func_node.child_by_field_name("body") {
        // First statement in body might be a docstring
        if let Some(first_stmt) = body.child(0) {
            if first_stmt.kind() == "expression_statement" {
                if let Some(expr) = first_stmt.child(0) {
                    if expr.kind() == "string" {
                        let text = node_text(expr, source);
                        // Remove quotes
                        let cleaned = text
                            .trim_start_matches("\"\"\"")
                            .trim_start_matches("'''")
                            .trim_start_matches('"')
                            .trim_start_matches('\'')
                            .trim_end_matches("\"\"\"")
                            .trim_end_matches("'''")
                            .trim_end_matches('"')
                            .trim_end_matches('\'')
                            .trim();
                        return Some(cleaned.to_string());
                    }
                }
            }
        }
    }
    None
}

// =============================================================================
// Purity Analysis
// =============================================================================

/// Analyze purity of a function
fn analyze_purity(func_node: Node, source: &[u8]) -> PurityInfo {
    let mut effects = Vec::new();
    let mut has_unknown_calls = false;
    let mut has_any_calls = false;

    analyze_purity_recursive(
        func_node,
        source,
        &mut effects,
        &mut has_unknown_calls,
        &mut has_any_calls,
    );

    if !effects.is_empty() {
        // Has side effects -> impure
        PurityInfo::impure(effects)
    } else if has_unknown_calls {
        // No known side effects, but calls unknown functions -> unknown
        PurityInfo::unknown().with_confidence("medium")
    } else if has_any_calls {
        // All calls resolved to known-pure builtins -> pure
        PurityInfo::pure()
    } else {
        // No calls detected at all (empty body or pure computation like a+b).
        // Absence of evidence is not evidence of purity — classify as unknown
        // with low confidence since we have nothing to base a purity claim on.
        PurityInfo::unknown().with_confidence("low")
    }
}

fn analyze_purity_recursive(
    node: Node,
    source: &[u8],
    effects: &mut Vec<String>,
    has_unknown_calls: &mut bool,
    has_any_calls: &mut bool,
) {
    match node.kind() {
        "global_statement" | "nonlocal_statement" => {
            if !effects.contains(&"global_write".to_string()) {
                effects.push("global_write".to_string());
            }
        }
        "assignment" | "augmented_assignment" => {
            // Check for attribute writes (self.x = ...)
            if let Some(left) = node.child_by_field_name("left") {
                if left.kind() == "attribute" && !effects.contains(&"attribute_write".to_string()) {
                    effects.push("attribute_write".to_string());
                }
            }
        }
        "call" => {
            *has_any_calls = true;
            let call_name = extract_call_name(node, source);
            if let Some(name) = &call_name {
                // Check for I/O operations
                for &io_op in IO_OPERATIONS {
                    if name == io_op || name.ends_with(&format!(".{}", io_op)) {
                        if !effects.contains(&"io".to_string()) {
                            effects.push("io".to_string());
                        }
                        return;
                    }
                }

                // Check for impure calls
                for &impure in IMPURE_CALLS {
                    if name == impure || name.ends_with(impure) {
                        if !effects.contains(&"io".to_string()) {
                            effects.push("io".to_string());
                        }
                        return;
                    }
                }

                // Check for collection mutations
                let method_name = name.split('.').next_back().unwrap_or(name);
                for &mutation in COLLECTION_MUTATIONS {
                    if method_name == mutation {
                        if !effects.contains(&"collection_modify".to_string()) {
                            effects.push("collection_modify".to_string());
                        }
                        return;
                    }
                }

                // Check if it's a known pure builtin
                let base = name.split('.').next_back().unwrap_or(name);
                if !PURE_BUILTINS.contains(&name.as_str()) && !PURE_BUILTINS.contains(&base) {
                    *has_unknown_calls = true;
                }
            }
        }
        _ => {}
    }

    // Recurse into children
    for child in node.children(&mut node.walk()) {
        analyze_purity_recursive(child, source, effects, has_unknown_calls, has_any_calls);
    }
}

/// Extract call name from a call node
fn extract_call_name(node: Node, source: &[u8]) -> Option<String> {
    if let Some(func) = node.child_by_field_name("function") {
        return Some(extract_name_from_expr(func, source));
    }
    // language-specific-bugs-v1 (P14.AGG14-16): Java / Kotlin / C# /
    // Scala / Swift / TS expose the callsite name through different
    // field names than Python's `function`. Try each in turn so the
    // multi-language call-kind acceptance above can extract a usable
    // name for `tldr explain`'s callees enumeration.
    for field in &["name", "method", "callee"] {
        if let Some(name_node) = node.child_by_field_name(field) {
            return Some(extract_name_from_expr(name_node, source));
        }
    }

    for child in node.children(&mut node.walk()) {
        match child.kind() {
            "identifier" | "simple_identifier" => {
                return Some(node_text(child, source).to_string())
            }
            "attribute"
            | "field_access"
            | "member_access_expression"
            | "navigation_expression"
            | "scoped_identifier" => return Some(extract_name_from_expr(child, source)),
            _ => continue,
        }
    }
    None
}

/// Extract a dotted name from an expression.
///
/// non-judgment-call-bugs-v1 (P17.AGG17-2): the previous fallback
/// (`_ => node_text(node, source).to_string()`) returned the *full
/// source text* for any non-identifier, non-Python-attribute node.
/// For TypeScript member-call chains like
/// `arr.flatMap(...).concat(...)` the call-expression's `function`
/// field is a `member_expression` whose `object` is itself a
/// `call_expression` — emitting `node_text(member_expression)`
/// produced multi-line strings (with embedded `\n` and full argument
/// source) as `callees[].name`. P17 flagged 54/270 callees
/// corrupted in `tldr explain emitter.ts emitWebIdl`.
///
/// Fix: explicitly handle the property-access node kinds emitted by
/// every multi-language tree-sitter grammar we accept and extract
/// just the rightmost property identifier (`property` /
/// `field` / `name` field, or the last `identifier` child).
/// `tldr context` already produced clean identifiers — this aligns
/// `tldr explain` with the same canonicalisation.
fn extract_name_from_expr(node: Node, source: &[u8]) -> String {
    match node.kind() {
        "identifier" | "simple_identifier" | "shorthand_property_identifier" => {
            node_text(node, source).to_string()
        }
        "attribute" => {
            let mut parts = Vec::new();
            let mut current = node;

            loop {
                if let Some(attr) = current.child_by_field_name("attribute") {
                    parts.push(node_text(attr, source).to_string());
                }

                if let Some(obj) = current.child_by_field_name("object") {
                    if obj.kind() == "attribute" {
                        current = obj;
                    } else if obj.kind() == "identifier" {
                        parts.push(node_text(obj, source).to_string());
                        break;
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }

            parts.reverse();
            parts.join(".")
        }
        // TypeScript / JavaScript: `obj.method` — emit just the
        // property name. Chained calls (`a.b().c`) reach here with
        // `object` itself a `call_expression`; we no longer emit the
        // full source, only the trailing property.
        "member_expression" => {
            if let Some(prop) = node.child_by_field_name("property") {
                return node_text(prop, source).to_string();
            }
            extract_trailing_identifier(node, source)
        }
        // Java / C# / PHP: `obj.method`
        "field_access" | "member_access_expression" => {
            for field in &["name", "field"] {
                if let Some(prop) = node.child_by_field_name(field) {
                    return node_text(prop, source).to_string();
                }
            }
            extract_trailing_identifier(node, source)
        }
        // Kotlin / Swift: `obj.method` (member access on a navigation
        // expression).
        "navigation_expression" => {
            if let Some(suffix) = node.child_by_field_name("suffix") {
                return extract_trailing_identifier(suffix, source);
            }
            extract_trailing_identifier(node, source)
        }
        // Go: `pkg.Symbol`
        "selector_expression" => {
            if let Some(field) = node.child_by_field_name("field") {
                return node_text(field, source).to_string();
            }
            extract_trailing_identifier(node, source)
        }
        // Rust: `mod::path::item` — emit just the trailing path segment
        "scoped_identifier" | "scoped_call_expression" => {
            if let Some(name) = node.child_by_field_name("name") {
                return node_text(name, source).to_string();
            }
            extract_trailing_identifier(node, source)
        }
        // Rust: `recv.method`
        "field_expression" => {
            if let Some(field) = node.child_by_field_name("field") {
                return node_text(field, source).to_string();
            }
            extract_trailing_identifier(node, source)
        }
        // Anything else: walk the subtree and grab the last identifier
        // we find. This is still better than emitting the full source
        // text and matches the behaviour of `tldr context` for
        // unfamiliar grammar shapes.
        _ => extract_trailing_identifier(node, source),
    }
}

/// Walk a subtree and return the rightmost identifier-like leaf token,
/// or — as an absolute last resort — the node's source text *up to the
/// first whitespace or `(` character* so we never emit the multi-line
/// argument list that produced AGG17-2.
fn extract_trailing_identifier(node: Node, source: &[u8]) -> String {
    fn walk<'a>(node: Node<'a>, found: &mut Option<Node<'a>>) {
        for child in node.children(&mut node.walk()) {
            match child.kind() {
                "identifier"
                | "simple_identifier"
                | "shorthand_property_identifier"
                | "property_identifier"
                | "field_identifier"
                | "type_identifier" => {
                    *found = Some(child);
                }
                _ => walk(child, found),
            }
        }
    }
    let mut last_id: Option<Node> = None;
    walk(node, &mut last_id);
    if let Some(n) = last_id {
        return node_text(n, source).to_string();
    }
    // Fallback: clip the raw source so we never emit multi-line text.
    let raw = node_text(node, source);
    let cut = raw
        .find(|c: char| c.is_whitespace() || c == '(' || c == '<')
        .unwrap_or(raw.len());
    raw[..cut].to_string()
}

// =============================================================================
// Complexity Analysis
// =============================================================================

/// Compute complexity metrics for a function
fn compute_complexity(func_node: Node) -> ComplexityInfo {
    // cross-command-consistency-v3 (P5.BUG-N2): the local
    // `count_complexity_recursive` walker is preserved for `num_blocks`,
    // `num_edges`, and `has_loops` (fields that are unique to
    // `ComplexityInfo` and have no canonical equivalent). The cyclomatic
    // value is intentionally discarded here — the caller `ExplainArgs::run`
    // overwrites it with the canonical
    // `tldr_core::calculate_complexity` value so `tldr explain` and
    // `tldr complexity` always agree on cyclomatic for the same function.
    let mut cyclomatic = 1; // Base complexity (overwritten by caller)
    let mut num_blocks = 1;
    let mut num_edges = 0;
    let mut has_loops = false;

    count_complexity_recursive(
        func_node,
        &mut cyclomatic,
        &mut num_blocks,
        &mut num_edges,
        &mut has_loops,
    );

    ComplexityInfo::new(cyclomatic, num_blocks, num_edges, has_loops)
}

fn count_complexity_recursive(
    node: Node,
    cyclomatic: &mut u32,
    num_blocks: &mut u32,
    num_edges: &mut u32,
    has_loops: &mut bool,
) {
    match node.kind() {
        "if_statement" | "elif_clause" => {
            *cyclomatic += 1;
            *num_blocks += 1;
            *num_edges += 2;
        }
        "for_statement" | "while_statement" => {
            *cyclomatic += 1;
            *num_blocks += 1;
            *num_edges += 2;
            *has_loops = true;
        }
        "try_statement" => {
            *cyclomatic += 1;
            *num_blocks += 1;
            *num_edges += 1;
        }
        "except_clause" => {
            *cyclomatic += 1;
            *num_blocks += 1;
            *num_edges += 1;
        }
        "and_operator" | "or_operator" => {
            *cyclomatic += 1;
        }
        "conditional_expression" => {
            // Ternary: x if cond else y
            *cyclomatic += 1;
            *num_edges += 1;
        }
        "list_comprehension"
        | "set_comprehension"
        | "dictionary_comprehension"
        | "generator_expression" => {
            *cyclomatic += 1;
            *has_loops = true;
        }
        _ => {}
    }

    for child in node.children(&mut node.walk()) {
        count_complexity_recursive(child, cyclomatic, num_blocks, num_edges, has_loops);
    }
}

// =============================================================================
// Call Graph Analysis
// =============================================================================

/// Find callees (functions called by this function)
fn find_callees(
    func_node: Node,
    source: &[u8],
    file_path: &str,
    local_functions: &HashSet<String>,
    language: Language,
) -> Vec<CallInfo> {
    let mut callees = Vec::new();
    find_callees_recursive(
        func_node,
        source,
        file_path,
        local_functions,
        language,
        &mut callees,
    );
    callees
}

fn find_callees_recursive(
    node: Node,
    source: &[u8],
    file_path: &str,
    local_functions: &HashSet<String>,
    language: Language,
    callees: &mut Vec<CallInfo>,
) {
    // language-specific-bugs-v1 (P14.AGG14-16): Java / Kotlin / C# tree-sitter
    // grammars expose callsites as `method_invocation` /
    // `invocation_expression` rather than the Python-shaped `call` node.
    // The original `node.kind() == "call"` filter therefore returned
    // `callees=[]` for every Java function in `tldr explain`, even when
    // the same function call site was visible in `context` and reachable
    // via the project call graph. Match the multi-language call-shaped
    // nodes already accepted elsewhere in this crate (`looks_like_call`
    // in `specs.rs` enumerates the same set).
    let is_call = matches!(
        node.kind(),
        "call"
            | "call_expression"
            | "invocation_expression"
            | "method_invocation"
            | "function_call"
            | "function_call_statement"
            | "macro_invocation"
            | "member_call_expression"
            | "function_call_expression"
            | "scoped_call_expression"
            | "nullsafe_member_call_expression"
    );
    if is_call {
        if let Some(name) = extract_call_name(node, source) {
            // cpp-explain-refs-cleanup-v1 (BUG-CPP-P20-04): tree-sitter-cpp
            // parses `static_cast<T>(x)`, `const_cast<T>(x)`,
            // `dynamic_cast<T>(x)`, and `reinterpret_cast<T>(x)` as
            // `call_expression` nodes whose `function` field is a
            // `template_function`. Extracted as plain identifier text, the
            // leading segment is the cast keyword, and `extract_call_name`
            // surfaces it as a callee — but no function call happens at
            // runtime (the cast keyword is a syntactic construct).
            // Similarly, preprocessor macros (`TIXMLASSERT`, `M_PI`,
            // `MIN`, …) by C/C++ convention use ALL_CAPS_WITH_UNDERSCORES
            // identifiers; they are not callable functions for the
            // purposes of explain's `callees[]` enumeration.
            if matches!(language, Language::Cpp | Language::C)
                && is_cpp_non_callee(node, &name)
            {
                // Recurse anyway so any real call buried inside the
                // cast's argument list (e.g. `static_cast<int>(foo())`)
                // still gets enumerated.
                for child in node.children(&mut node.walk()) {
                    find_callees_recursive(
                        child,
                        source,
                        file_path,
                        local_functions,
                        language,
                        callees,
                    );
                }
                return;
            }

            // Get base name for local function check
            let base_name = name.split('.').next().unwrap_or(&name);

            // Add if it's a local function or a known call
            let file = if local_functions.contains(base_name) {
                file_path.to_string()
            } else {
                "<external>".to_string()
            };

            // Avoid duplicates.
            // cross-cutting-and-clear-fix-bugs-v1 (P18.Pattern-B): the
            // same call site can yield two emissions in some languages —
            // a bare-name (`trickleDownMin`) AND a qualified-name
            // (`Heap.trickleDownMin`) — when the call expression is
            // disambiguated by an outer enclosing-class scope. Dedup by
            // (line, last_segment) so the call is reported once. Falls
            // back to the legacy exact-name check when line numbers
            // cannot be resolved.
            let line = get_line_number(node);
            let last_seg = name.rsplit('.').next().unwrap_or(&name).to_string();
            if !callees.iter().any(|c| {
                c.name == name
                    || (c.line == line
                        && c.name.rsplit('.').next().unwrap_or(&c.name) == last_seg)
            }) {
                callees.push(CallInfo::new(name, file, line));
            }
        }
    }

    for child in node.children(&mut node.walk()) {
        find_callees_recursive(child, source, file_path, local_functions, language, callees);
    }
}

/// cpp-explain-refs-cleanup-v1 (BUG-CPP-P20-04): return `true` when a
/// C/C++ `call_expression` node should NOT be reported as a callee
/// because it is either (a) a `*_cast<T>(x)` cast keyword or (b) a
/// preprocessor-macro invocation matching the
/// ALL_CAPS_WITH_UNDERSCORES naming convention.
///
/// Heuristics:
///
/// * `function` field is a `template_function` whose `name`/leading
///   identifier is `static_cast`, `const_cast`, `dynamic_cast`, or
///   `reinterpret_cast`. These are syntactic casts, not function calls.
/// * `function` field is a bare `identifier` whose text is entirely
///   uppercase, digits, and underscores AND begins with an uppercase
///   letter. C/C++ style guides (Google, LLVM, Mozilla, ISO) reserve
///   this spelling for preprocessor macros — flagging them as callees
///   produces noise in `explain` output (BUG-CPP-P20-04 observed
///   `TIXMLASSERT` polluting the tinyxml2 dataset).
fn is_cpp_non_callee(node: Node, name: &str) -> bool {
    // Cast keywords (template_function-shaped). The plain `name` extracted
    // above for `static_cast<int>(x)` is just `static_cast` — the trailing
    // type argument is dropped by extract_trailing_identifier — so we can
    // string-compare directly.
    let cast_keywords = [
        "static_cast",
        "const_cast",
        "dynamic_cast",
        "reinterpret_cast",
    ];
    if cast_keywords.contains(&name) {
        // Sanity check: the underlying function field should be a
        // template_function so we don't accidentally drop a real
        // user-defined function (vanishingly unlikely given naming
        // collisions, but cheap to verify).
        if let Some(func) = node.child_by_field_name("function") {
            if func.kind() == "template_function" {
                return true;
            }
        }
        // Fall through: if the function shape is unexpected, prefer
        // false-positive-noise over silently dropping it.
    }

    // Preprocessor macro convention: ALL_CAPS_WITH_UNDERSCORES,
    // starting with an uppercase letter, length >= 2 (single-letter
    // identifiers like `T` are likely template parameters surfaced
    // through an unusual AST path; skip those). Requires the function
    // field be a plain identifier — qualified / member / template
    // shapes are real calls.
    if name.len() >= 2
        && name.chars().next().is_some_and(|c| c.is_ascii_uppercase())
        && name
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        // Require at least one underscore or be entirely uppercase letters >= 3 chars
        // so we don't accidentally drop two-letter uppercase symbols
        // (e.g. enum-like identifiers passed to a function-shaped macro).
        && (name.contains('_') || name.len() >= 3)
    {
        if let Some(func) = node.child_by_field_name("function") {
            if func.kind() == "identifier" {
                return true;
            }
        }
    }

    false
}

/// Find callers (functions that call this function) - searches the entire file
fn find_callers(
    root: Node,
    source: &[u8],
    target_function: &str,
    file_path: &str,
    func_kinds: &[&str],
) -> Vec<CallInfo> {
    let mut callers = Vec::new();
    find_callers_in_file(
        root,
        source,
        target_function,
        file_path,
        &mut callers,
        None,
        func_kinds,
    );
    callers
}

fn find_callers_in_file(
    node: Node,
    source: &[u8],
    target_function: &str,
    file_path: &str,
    callers: &mut Vec<CallInfo>,
    current_function: Option<&str>,
    func_kinds: &[&str],
) {
    if func_kinds.contains(&node.kind()) {
        // Get this function's name
        let mut func_name = None;

        // Try field name first
        if let Some(name_node) = node.child_by_field_name("name") {
            func_name = Some(node_text(name_node, source));
        } else {
            // Fallback: search for identifier child
            for child in node.children(&mut node.walk()) {
                if child.kind() == "identifier" {
                    func_name = Some(node_text(child, source));
                    break;
                }
            }
        }

        // Recurse with this function as current
        for child in node.children(&mut node.walk()) {
            find_callers_in_file(
                child,
                source,
                target_function,
                file_path,
                callers,
                func_name,
                func_kinds,
            );
        }
        return;
    } else if node.kind() == "call" {
        if let Some(name) = extract_call_name(node, source) {
            // Check if this call is to our target function
            let base = name.split('.').next_back().unwrap_or(&name);
            if base == target_function || name == target_function {
                if let Some(caller_name) = current_function {
                    // Avoid duplicates and self-references
                    if caller_name != target_function
                        && !callers.iter().any(|c| c.name == caller_name)
                    {
                        callers.push(CallInfo::new(caller_name, file_path, get_line_number(node)));
                    }
                }
            }
        }
    }

    for child in node.children(&mut node.walk()) {
        find_callers_in_file(
            child,
            source,
            target_function,
            file_path,
            callers,
            current_function,
            func_kinds,
        );
    }
}

/// Collect all function names in a file
fn collect_function_names(root: Node, source: &[u8], func_kinds: &[&str]) -> HashSet<String> {
    let mut names = HashSet::new();
    collect_function_names_recursive(root, source, &mut names, func_kinds);
    names
}

fn collect_function_names_recursive(
    node: Node,
    source: &[u8],
    names: &mut HashSet<String>,
    func_kinds: &[&str],
) {
    if func_kinds.contains(&node.kind()) {
        // Try field name first
        if let Some(name_node) = node.child_by_field_name("name") {
            names.insert(node_text(name_node, source).to_string());
        } else {
            // Fallback: search for identifier child
            for child in node.children(&mut node.walk()) {
                if child.kind() == "identifier" {
                    names.insert(node_text(child, source).to_string());
                    break;
                }
            }
        }
    }

    for child in node.children(&mut node.walk()) {
        collect_function_names_recursive(child, source, names, func_kinds);
    }
}

// =============================================================================
// Text Formatting
// =============================================================================

/// Format an ExplainReport as human-readable text
fn format_explain_text(report: &ExplainReport) -> String {
    let mut lines = Vec::new();

    lines.push(format!("Function: {}", report.function_name));
    lines.push(format!("File: {}", report.file));
    lines.push(format!("Lines: {}-{}", report.line_start, report.line_end));
    lines.push(format!("Language: {}", report.language));
    lines.push(String::new());

    // Signature
    lines.push("Signature:".to_string());
    if report.signature.is_async {
        lines.push("  async: yes".to_string());
    }
    lines.push(format!("  Parameters: {}", report.signature.params.len()));
    for param in &report.signature.params {
        let type_str = param.type_hint.as_deref().unwrap_or("untyped");
        lines.push(format!("    - {}: {}", param.name, type_str));
    }
    if let Some(ref ret) = report.signature.return_type {
        lines.push(format!("  Returns: {}", ret));
    }
    if !report.signature.decorators.is_empty() {
        lines.push(format!(
            "  Decorators: {}",
            report.signature.decorators.join(", ")
        ));
    }
    if let Some(ref doc) = report.signature.docstring {
        let preview = if doc.len() > 100 {
            format!("{}...", &doc[..100])
        } else {
            doc.clone()
        };
        lines.push(format!("  Docstring: {}", preview));
    }
    lines.push(String::new());

    // Purity
    lines.push("Purity:".to_string());
    lines.push(format!(
        "  Classification: {}",
        report.purity.classification
    ));
    lines.push(format!("  Confidence: {}", report.purity.confidence));
    if !report.purity.effects.is_empty() {
        lines.push(format!("  Effects: {}", report.purity.effects.join(", ")));
    }
    lines.push(String::new());

    // Complexity
    if let Some(ref cx) = report.complexity {
        lines.push("Complexity:".to_string());
        lines.push(format!("  Cyclomatic: {}", cx.cyclomatic));
        lines.push(format!("  Blocks: {}", cx.num_blocks));
        lines.push(format!("  Edges: {}", cx.num_edges));
        lines.push(format!("  Has loops: {}", cx.has_loops));
        // rust-explain-cognitive-v1: surface cognitive in the text
        // formatter too when the join succeeded, so the human-readable
        // view stays consistent with the JSON output.
        if let Some(cog) = cx.cognitive {
            lines.push(format!("  Cognitive: {}", cog));
        }
        lines.push(String::new());
    }

    // Callers
    if !report.callers.is_empty() {
        lines.push(format!("Callers ({}):", report.callers.len()));
        for caller in &report.callers {
            lines.push(format!(
                "  - {} ({}:{})",
                caller.name, caller.file, caller.line
            ));
        }
        lines.push(String::new());
    }

    // Callees
    if !report.callees.is_empty() {
        lines.push(format!("Callees ({}):", report.callees.len()));
        for callee in &report.callees {
            lines.push(format!(
                "  - {} ({}:{})",
                callee.name, callee.file, callee.line
            ));
        }
    }

    lines.join("\n")
}

// =============================================================================
// Project-wide Call Graph Enrichment
// (explain-cross-command-consistency-v1: route callers/callees through the
// canonical project-wide call graph used by `impact`/`references`/`context`,
// matching the `cross-command-consistency-v3` pattern that aligned cyclomatic
// between `explain` and `complexity`.)
// =============================================================================

/// Determine a project root for `file`. Walks up from the file's parent
/// directory until a recognised project marker is found
/// (`Cargo.toml`, `package.json`, `go.mod`, `pyproject.toml`, `setup.py`,
/// `pom.xml`, `build.gradle`, `.git`). Falls back to the immediate parent
/// directory so the call graph at least scans alongside files (which still
/// surfaces same-directory callers / callees that the per-file walker
/// misses).
///
/// explain-callers-cross-lang-v1 (P15.AGG15-1): canonicalize `file` first so
/// the walk-up traverses real ancestor directories. Without canonicalization,
/// a relative input like `lib/application.js` produces parent components
/// `["lib", ""]`; the empty-path component then `join("package.json")`
/// resolves against CWD as `package.json` and "exists", causing
/// `explain_project_root` to return the empty path. `build_project_call_graph`
/// invoked with an empty path then fails to discover any source files,
/// leaving `report.callers` empty even though `tldr impact` (which receives
/// an explicit path) returns the correct callers. Canonicalizing first
/// converts the input to an absolute path so each ancestor directory is real.
fn explain_project_root(file: &std::path::Path) -> std::path::PathBuf {
    let absolute = file
        .canonicalize()
        .unwrap_or_else(|_| {
            // Canonicalize failed (file may not exist on disk via this path).
            // Best-effort absolute form: join CWD with the relative input.
            if file.is_absolute() {
                file.to_path_buf()
            } else {
                std::env::current_dir()
                    .map(|cwd| cwd.join(file))
                    .unwrap_or_else(|_| file.to_path_buf())
            }
        });
    let parent = absolute
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let markers = [
        "Cargo.toml",
        "package.json",
        "go.mod",
        "pyproject.toml",
        "setup.py",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        ".git",
    ];
    let mut cursor: Option<&std::path::Path> = Some(&parent);
    while let Some(dir) = cursor {
        // Skip empty-path components: an empty PathBuf joins as a relative
        // CWD-rooted path which can falsely "exist" for markers that live
        // in CWD but not in the (non-existent) empty ancestor directory.
        if dir.as_os_str().is_empty() {
            cursor = dir.parent();
            continue;
        }
        for m in &markers {
            if dir.join(m).exists() {
                return dir.to_path_buf();
            }
        }
        cursor = dir.parent();
    }
    parent
}

/// Return true if `edge_path` and `target_file` refer to the same file.
/// Compares canonicalized paths first; falls back to suffix / equality
/// match if canonicalization fails (e.g. relative paths from the call
/// graph against an absolute target).
fn paths_equivalent(edge_path: &std::path::Path, target_file: &std::path::Path) -> bool {
    if edge_path == target_file {
        return true;
    }
    let edge_canon = edge_path.canonicalize().ok();
    let target_canon = target_file.canonicalize().ok();
    if let (Some(a), Some(b)) = (edge_canon.as_ref(), target_canon.as_ref()) {
        if a == b {
            return true;
        }
    }
    // Fall back to suffix match in either direction (relative vs absolute).
    if edge_path.ends_with(target_file) || target_file.ends_with(edge_path) {
        return true;
    }
    false
}

/// Strict last-segment compare for qualified names
/// (mirrors `tldr_core::analysis::impact::last_segment` so the explain
/// merge applies the same matching rules `impact` uses).
fn explain_last_segment(qualified: &str) -> &str {
    let dot_idx = qualified.rfind('.');
    let coloncolon_idx = qualified.rfind("::").map(|i| i + 1);
    let cut = match (dot_idx, coloncolon_idx) {
        (Some(d), Some(c)) => Some(d.max(c)),
        (Some(d), None) => Some(d),
        (None, Some(c)) => Some(c),
        (None, None) => None,
    };
    match cut {
        Some(i) if i < qualified.len() => &qualified[i + 1..],
        _ => qualified,
    }
}

/// Two function names are equivalent when their last segments match, or
/// one is a qualified form of the other.
fn explain_names_match(candidate: &str, target: &str) -> bool {
    if candidate == target {
        return true;
    }
    if explain_last_segment(candidate) == target {
        return true;
    }
    let target_has_qualifier = target.contains('.') || target.contains("::");
    if target_has_qualifier {
        let target_tail = explain_last_segment(target);
        if candidate == target_tail {
            return true;
        }
        if explain_last_segment(candidate) == target_tail {
            return true;
        }
    }
    false
}

/// Path-aware caller dedup: returns true if `report.callers` already
/// contains an entry equivalent to `(name, file)`. ux-and-explain-completeness-v1
/// (P12.AGG12-1): the previous string-equality check missed the relative-vs-
/// absolute path mismatch between the per-file walker (absolute) and the
/// project-graph (relative-to-root), causing duplicate `locate_app` callers
/// in `flask` (one with `line=0`, one with the real line number).
fn caller_already_present(
    callers: &[CallInfo],
    candidate_name: &str,
    candidate_file: &str,
) -> bool {
    let candidate_path = std::path::Path::new(candidate_file);
    callers.iter().any(|c| {
        if !names_match(&c.name, candidate_name) && !names_match(candidate_name, &c.name) {
            return false;
        }
        let existing_path = std::path::Path::new(&c.file);
        c.file == candidate_file || paths_equivalent(existing_path, candidate_path)
    })
}

/// Path-aware callee dedup, mirroring `caller_already_present`.
fn callee_already_present(
    callees: &[CallInfo],
    candidate_name: &str,
    candidate_file: &str,
) -> bool {
    let candidate_path = std::path::Path::new(candidate_file);
    callees.iter().any(|c| {
        if !names_match(&c.name, candidate_name) && !names_match(candidate_name, &c.name) {
            return false;
        }
        if c.file == "<external>" {
            return true;
        }
        let existing_path = std::path::Path::new(&c.file);
        c.file == candidate_file || paths_equivalent(existing_path, candidate_path)
    })
}

/// explain-callees-in-project-v1 (v0.4.2 M-019): when the per-file walker
/// (`find_callees`) emits a placeholder `file: "<external>"` for a callee
/// whose name we now know is in-project (via the project call graph
/// edge's `dst_func`/`dst_file`), upgrade the existing entry's file in
/// place rather than adding a duplicate. Returns `true` if any entry was
/// upgraded — the caller should then `continue` rather than push a new
/// row (which would create a Pattern-B bare+qualified duplicate of the
/// kind cross-cutting-and-clear-fix-bugs-v1 addressed).
///
/// Matching rules:
///   - Names match via `names_match` in either direction (per the
///     existing `callee_already_present` convention; this handles the
///     bare-vs-qualified `CleanPath` / `pkg.CleanPath` shape).
///   - The existing entry's file is literally `"<external>"` (the
///     placeholder marker). Entries with real files are NOT touched.
fn upgrade_external_callee(
    callees: &mut [CallInfo],
    candidate_name: &str,
    candidate_file: &str,
) -> bool {
    let mut upgraded = false;
    for c in callees.iter_mut() {
        if c.file != "<external>" {
            continue;
        }
        if !names_match(&c.name, candidate_name) && !names_match(candidate_name, &c.name) {
            continue;
        }
        // Promote the file to the real in-project path. The downstream
        // `restore_explain_path_shape` pass will normalise this to the
        // user-input shape uniformly across all emitted paths.
        c.file = candidate_file.to_string();
        upgraded = true;
    }
    upgraded
}

/// explain-callees-in-project-v1 (v0.4.2 M-019): final fallback pass for
/// callees whose file is still the `<external>` placeholder after the
/// edge-iteration above. Scans the entire project call graph for ANY
/// edge whose `dst_func` matches the callee's name (bare or qualified).
/// If a unique in-project file is found, the callee's `file` is
/// upgraded in place.
///
/// Why a second pass: the edge-iteration above only fires when the
/// graph contains an edge ROOTED at the function we're explaining
/// (`src_func == function && src_file == file`). The call-graph V2
/// resolver may MISS some call-sites — especially for cross-language
/// shapes where the callsite is detected but the binding to the
/// declaration isn't resolved. The declaration itself is still
/// indexed (because some OTHER caller's edge points at it), and that
/// `dst_file` is a reliable signal that the callee lives in-project.
///
/// We accept the resolution only when ALL matching edges agree on the
/// same `dst_file` (or one of them lives in `file` itself — preferring
/// same-file). Ambiguous resolution leaves `<external>` in place so
/// the downstream path-shape pass doesn't fabricate an incorrect
/// attribution.
fn resolve_external_callees_via_graph(
    callees: &mut [CallInfo],
    graph: &tldr_core::types::ProjectCallGraph,
    self_file: &std::path::Path,
) {
    use std::collections::HashSet;
    for c in callees.iter_mut() {
        if c.file != "<external>" {
            continue;
        }
        // Collect every dst_file in the graph whose dst_func matches
        // this callee name. Use a dedup set so multiple call sites to
        // the same target don't bias the "ambiguous" check.
        let mut dst_files: HashSet<std::path::PathBuf> = HashSet::new();
        let mut prefer_self_file: Option<std::path::PathBuf> = None;
        for edge in graph.edges() {
            if !names_match(&edge.dst_func, &c.name) && !names_match(&c.name, &edge.dst_func) {
                continue;
            }
            dst_files.insert(edge.dst_file.clone());
            // If a matching edge's dst_file is the same as self_file,
            // strongly prefer that — same-file definitions are the
            // common case for the c47/cpp46 audit cells.
            if paths_equivalent(&edge.dst_file, self_file) && prefer_self_file.is_none() {
                prefer_self_file = Some(edge.dst_file.clone());
            }
        }
        if let Some(p) = prefer_self_file {
            c.file = p.display().to_string();
            continue;
        }
        // Accept resolution only when there's a single unique
        // dst_file (no ambiguity). The downstream path-shape pass
        // will normalise it to the user-input shape.
        if dst_files.len() == 1 {
            if let Some(p) = dst_files.into_iter().next() {
                c.file = p.display().to_string();
            }
        }
    }
}

/// language-specific-bugs-v1 (P14.AGG14-16): given a caller file and the
/// caller-function name + target-function name, scan the file's source
/// looking for a call site to `target_function` inside the body of
/// `caller_function`. Returns the 1-indexed line of the first matching
/// call site, or `None` if no match is found.
///
/// Implementation: read file -> parse with the file's language ->
/// locate the function-shaped node whose name matches `caller_function`
/// -> walk its descendants for any call-shaped node whose callee
/// (extracted via `extract_call_name`) tail-matches `target_function`.
fn locate_call_in_caller_file(
    file: &std::path::Path,
    caller_function: &str,
    target_function: &str,
) -> Option<u32> {
    use std::fs;
    let language = Language::from_path(file)?;
    let source = fs::read_to_string(file).ok()?;
    let func_kinds = get_function_node_kinds(language);
    // Class node kinds — kept inline (a tiny static slice) to avoid
    // pulling in `interface.rs::class_node_kinds`, which is not pub.
    let class_kinds: &[&str] = &[
        "class_definition",
        "class_declaration",
        "interface_declaration",
        "struct_item",
        "enum_item",
        "trait_item",
        "impl_item",
        "class_specifier",
        "struct_specifier",
        "enum_declaration",
        "record_declaration",
        "object_declaration",
        "object_definition",
        "trait_definition",
        "protocol_declaration",
        "extension_declaration",
        "module",
    ];

    let mut parser = get_parser(language).ok()?;
    let tree = parser.parse(&source, None)?;
    let source_bytes = source.as_bytes();

    // Strip any class qualifier from `caller_function` for tail matching:
    // `OwnerController.processFindForm` -> `processFindForm`.
    let caller_tail = caller_function
        .rsplit('.')
        .next()
        .unwrap_or(caller_function);
    let target_tail = target_function
        .rsplit('.')
        .next()
        .unwrap_or(target_function);

    fn descend<'a>(
        node: tree_sitter::Node<'a>,
        source: &[u8],
        func_kinds: &[&str],
        class_kinds: &[&str],
        caller_tail: &str,
        target_tail: &str,
        in_target_func: bool,
    ) -> Option<u32> {
        // When we enter a function node whose name matches caller_tail,
        // turn on `in_target_func` for the descent.
        let kind = node.kind();
        let is_func_decl = func_kinds.contains(&kind);
        let mut now_in = in_target_func;
        if is_func_decl {
            // Try to read this function's name. Reuse the same fallback
            // logic as `find_callers_in_file`: prefer the `name` field,
            // else the first identifier child.
            let mut name: Option<String> = None;
            if let Some(name_node) = node.child_by_field_name("name") {
                name = Some(node_text(name_node, source).to_string());
            } else {
                for child in node.children(&mut node.walk()) {
                    if matches!(child.kind(), "identifier" | "simple_identifier") {
                        name = Some(node_text(child, source).to_string());
                        break;
                    }
                }
            }
            if let Some(n) = name.as_deref() {
                if explain_names_match(n, caller_tail) || n == caller_tail {
                    now_in = true;
                }
            }
        }

        // While inside the caller function, look for any call node whose
        // tail-name matches target_tail.
        if now_in {
            let is_call = matches!(
                kind,
                "call"
                    | "call_expression"
                    | "invocation_expression"
                    | "method_invocation"
                    | "function_call"
                    | "function_call_statement"
                    | "macro_invocation"
                    | "member_call_expression"
                    | "function_call_expression"
                    | "scoped_call_expression"
                    | "nullsafe_member_call_expression"
            );
            if is_call {
                if let Some(callee) = extract_call_name(node, source) {
                    let tail = callee.rsplit('.').next().unwrap_or(&callee);
                    if tail == target_tail {
                        return Some(node.start_position().row as u32 + 1);
                    }
                }
            }
        }

        // Avoid descending into nested classes when we've already
        // matched the outer caller — but DO descend into nested
        // function definitions so closures/lambda bodies are searched.
        if class_kinds.contains(&kind) && now_in && !is_func_decl {
            // Don't descend into nested classes — they have their own
            // method scope.
            return None;
        }

        for child in node.children(&mut node.walk()) {
            if let Some(line) = descend(
                child,
                source,
                func_kinds,
                class_kinds,
                caller_tail,
                target_tail,
                now_in,
            ) {
                return Some(line);
            }
        }
        None
    }

    descend(
        tree.root_node(),
        source_bytes,
        func_kinds,
        class_kinds,
        caller_tail,
        target_tail,
        false,
    )
}

/// Enrich `report.callers` and `report.callees` with cross-file results
/// derived from the project-wide call graph (`build_project_call_graph` /
/// `impact_analysis_with_ast_fallback`) — the same data source used by
/// `tldr impact`, `tldr references`, and `tldr context`. Same-file
/// results from the existing per-file walker are preserved; cross-file
/// callers/callees that the per-file walker cannot see by construction
/// are appended (deduplicated path-aware by `name+file`). Any failure
/// here is silently ignored so explain still returns its other fields
/// when the project graph cannot be built.
fn enrich_with_project_graph(
    report: &mut ExplainReport,
    file: &std::path::Path,
    function: &str,
    language: Language,
) {
    let project_root = explain_project_root(file);
    let graph = match build_project_call_graph(&project_root, language, None, true) {
        Ok(g) => g,
        Err(_) => return,
    };

    // critical-regressions-v1 (P13.AGG13-2): when the user supplies a Swift
    // file that defines the function in an `extension Heap { ... }` (or a
    // nested type's extension), the Swift call-graph builder may attribute
    // the target's `dst_file` to the FIRST file it processed for that
    // class (e.g. `Heap.swift`), not the file where the method actually
    // lives (`Heap+UnsafeHandle.swift`). The strict `paths_equivalent`
    // filter then drops every real caller. Confirm whether the function
    // truly lives in the user-supplied file by AST scan; if so, accept
    // callers from any homonym target.
    let function_defined_in_file = function_is_defined_in_file(file, function, language);
    // Callers: use the same path `tldr impact` uses so the results agree.
    if let Ok(impact) = impact_analysis_with_ast_fallback(
        &graph,
        function,
        1, // direct callers only (consistent with the per-file walker)
        None,
        &project_root,
        language,
    ) {
        for tree in impact.targets.values() {
            // Only enrich when the target's file matches our subject file —
            // explain is per-function-per-file, so cross-file callers of a
            // homonym in a different file should not be merged in. The
            // `function_defined_in_file` escape hatch covers the Swift
            // extension case described above.
            if !paths_equivalent(&tree.file, file) && !function_defined_in_file {
                continue;
            }
            for caller in &tree.callers {
                let caller_file = caller.file.display().to_string();
                let caller_name = caller.function.clone();
                // Avoid self-references and duplicates.
                if explain_names_match(&caller_name, function)
                    && paths_equivalent(&caller.file, file)
                {
                    continue;
                }
                if caller_already_present(&report.callers, &caller_name, &caller_file) {
                    continue;
                }
                // language-specific-bugs-v1 (P14.AGG14-16): the call-graph
                // edge does not carry the source line of the callsite,
                // so the original code unconditionally pushed
                // `line: 0` — which made `tldr explain` agree with itself
                // on a bogus value across every Java/Kotlin/CSharp
                // caller. Resolve the line by scanning the caller file
                // for a callsite to `function` inside the named caller
                // function. Falls back to 0 only when no match is found.
                //
                // CallerTree's `file` is a project-relative path; resolve
                // it against the project root so `locate_call_in_caller_file`
                // can read the source.
                let abs_caller_file = if caller.file.is_absolute() {
                    caller.file.clone()
                } else {
                    project_root.join(&caller.file)
                };
                let line = locate_call_in_caller_file(
                    &abs_caller_file,
                    &caller_name,
                    function,
                )
                .unwrap_or(0);
                report
                    .callers
                    .push(CallInfo::new(caller_name, caller_file, line));
            }
        }
    }

    // Callees: scan project edges for `src_func == function` defined in `file`.
    for edge in graph.edges() {
        if !explain_names_match(&edge.src_func, function) {
            continue;
        }
        if !paths_equivalent(&edge.src_file, file) {
            continue;
        }
        let dst_file = edge.dst_file.display().to_string();
        let dst_name = edge.dst_func.clone();
        // Skip self-recursion duplicates of the same target name.
        if explain_names_match(&dst_name, function)
            && paths_equivalent(&edge.dst_file, file)
        {
            continue;
        }
        // explain-callees-in-project-v1 (v0.4.2 M-019): when an `<external>`
        // placeholder already exists for this callee name, UPGRADE it
        // in place rather than skipping the edge entirely. The per-file
        // walker (`find_callees`) defaults to `<external>` whenever a
        // callee name isn't recognized as a same-file local; the
        // project-wide call graph reliably knows the real `dst_file`
        // (`tldr calls`/`tldr impact` use the same source). Without
        // this promotion, the audit observed `<external>` for callees
        // that are obviously in-project (c47 sdsnewlen, go47 CleanPath,
        // java47 getLastName, kotlin47 offsetIn, etc.).
        if upgrade_external_callee(&mut report.callees, &dst_name, &dst_file) {
            continue;
        }
        if callee_already_present(&report.callees, &dst_name, &dst_file) {
            continue;
        }
        // language-specific-bugs-v1 (P14.AGG14-16): same line-recovery
        // approach as for callers. The call-graph edge does not carry
        // the source line of the callsite, so look it up by AST scan.
        // The caller here is `function` itself (the function we are
        // explaining); its file is `file`.
        let line = locate_call_in_caller_file(file, function, &dst_name).unwrap_or(0);
        // cross-cutting-and-clear-fix-bugs-v1 (P18.Pattern-B): line-aware
        // dedup. When `find_callees` already emitted a bare-name entry
        // for this call site (e.g. `trickleDownMin` at line 382),
        // adding the call-graph's qualified-name version
        // (`Heap.trickleDownMin` at the same line, possibly with a
        // relative-vs-absolute path mismatch the `paths_equivalent`
        // check missed) would re-introduce the Pattern-B bare+qualified
        // duplicate. Skip when an entry sharing the same line and the
        // same last-segment already exists.
        if line > 0 {
            let last_seg = dst_name
                .rsplit('.')
                .next()
                .unwrap_or(&dst_name)
                .to_string();
            if report.callees.iter().any(|c| {
                c.line == line
                    && c.name.rsplit('.').next().unwrap_or(&c.name) == last_seg
            }) {
                continue;
            }
        }
        report
            .callees
            .push(CallInfo::new(dst_name, dst_file, line));
    }

    // explain-callees-in-project-v1 (v0.4.2 M-019): final fallback for
    // any callee still flagged `<external>` after the edge-iteration
    // above. The V2 call-graph resolver may miss the binding at THIS
    // call site even when the declaration itself is indexed (via other
    // call sites' edges). Scan the whole graph for `dst_func` matches
    // and promote a unique resolution.
    resolve_external_callees_via_graph(&mut report.callees, &graph, file);

    // sibling-resolver-gaps-v1 (P14.AGG14-14): the Swift call-graph
    // builder may attribute a callee's `dst_file` to a test file that
    // *uses* the method (e.g. `Tests/HeapTests/HeapTests.swift`) rather
    // than the file that *defines* it (e.g.
    // `Sources/HeapModule/Heap+UnsafeHandle.swift`). For each callee
    // whose attributed file does NOT define a matching function, search
    // the project for a definition file and rewrite `.file` to the
    // canonical definition. Skip if no unique definition is found
    // (preserves the original attribution as a best-effort fallback).
    if language == Language::Swift {
        // Build a unique candidate set from the call-graph edges, plus
        // any same-language file under the project root the walker
        // already visited. Resolve relative paths against `project_root`
        // so `function_is_defined_in_file` can call `extract_file`
        // successfully regardless of whether the call-graph emitted
        // relative or absolute paths.
        let resolve = |p: &std::path::Path| -> std::path::PathBuf {
            if p.is_absolute() {
                p.to_path_buf()
            } else {
                project_root.join(p)
            }
        };
        let mut cand_set: std::collections::HashSet<std::path::PathBuf> =
            std::collections::HashSet::new();
        for e in graph.edges() {
            cand_set.insert(resolve(&e.dst_file));
            cand_set.insert(resolve(&e.src_file));
        }
        let candidates: Vec<std::path::PathBuf> = cand_set.into_iter().collect();
        for callee in report.callees.iter_mut() {
            let attributed_file = resolve(std::path::Path::new(&callee.file));
            // If the attributed file already defines the callee, leave
            // it alone (the common, correct case).
            if function_is_defined_in_file(&attributed_file, &callee.name, language) {
                continue;
            }
            // Collect every project file (from the graph's edges) that
            // actually defines the callee, then prefer the
            // non-test-scope one.
            let mut def_files: Vec<std::path::PathBuf> = Vec::new();
            for cand in &candidates {
                if function_is_defined_in_file(cand, &callee.name, language) {
                    def_files.push(cand.clone());
                }
            }
            if def_files.is_empty() {
                continue;
            }
            // Prefer files whose path does NOT contain `/Tests/` or
            // `/test/` over those that do. This matches the convention
            // that swift-collections etc. keep production sources under
            // `Sources/` and tests under `Tests/`.
            def_files.sort_by_key(|p| {
                let s = p.to_string_lossy().to_lowercase();
                let is_test = s.contains("/tests/")
                    || s.contains("/test/")
                    || s.contains("test.swift")
                    || s.ends_with("tests.swift");
                if is_test {
                    1
                } else {
                    0
                }
            });
            if let Some(canonical) = def_files.first() {
                // Emit a project-relative path when possible (matches
                // the existing convention used by callees from the
                // call-graph edges) so downstream consumers see a
                // homogeneous shape.
                let display = canonical
                    .strip_prefix(&project_root)
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|_| canonical.display().to_string());
                callee.file = display;
            }
        }
    }
}

/// Enrich `report.callers` using `find_references` for languages whose
/// project call graph misses cross-file caller edges (notably C# and
/// other class-heavy languages).
///
/// ux-and-explain-completeness-v1 (P12.AGG12-1): the call-graph builder
/// for some languages (CSharp, Kotlin, Scala, OCaml functor wrappers,
/// etc.) under-reports cross-file edges — `tldr references` finds calls
/// that `tldr impact` cannot. Mirror that same data source here so
/// `explain.callers` is non-empty whenever any reference of kind `call`
/// exists.
///
/// For each Call reference found, locate the enclosing function in the
/// caller file via `extract_file` (matches the surface used by
/// `enumerate_function_lines`). Skip self-references (call inside the
/// target function in the target file). Dedup path-aware against
/// existing entries.
fn enrich_with_references(
    report: &mut ExplainReport,
    file: &std::path::Path,
    function: &str,
    language: Language,
) {
    let project_root = explain_project_root(file);
    let mut options = ReferencesOptions::new();
    options.kinds = Some(vec![ReferenceKind::Call]);
    options.language = Some(language.as_str().to_string());
    options.limit = Some(500); // generous; explain doesn't need to return everything

    let report_refs = match find_references(function, &project_root, &options) {
        Ok(r) => r,
        Err(_) => return,
    };

    // Cache of caller-file -> Vec<(function_name, line_start, line_end)> so we
    // don't re-parse the same file repeatedly when multiple call sites
    // share an enclosing function file.
    use std::collections::HashMap;
    let mut file_funcs_cache: HashMap<std::path::PathBuf, Vec<(String, u32, u32)>> = HashMap::new();

    for r in &report_refs.references {
        push_caller_from_reference(report, file, function, r, &mut file_funcs_cache);
    }

    // critical-regressions-v1 (P13.AGG13-12): Lua's cross-module-alias call
    // graph does not always resolve `<alias>.<method>(...)` to the
    // matching `function m.<method>` definition (the `m.reset` case
    // happened to resolve via the call-graph but `m.open` did not — see
    // audit cell). Augment by querying references for the bare method
    // name and accepting only Call hits whose context contains `\.<method>(`,
    // i.e. truly a method invocation through an alias. This is per-language
    // because other languages' references are already covered by the
    // primary call-graph path.
    if matches!(language, Language::Lua | Language::Luau) {
        if let Some(bare) = function.split('.').next_back() {
            if bare != function && !bare.is_empty() {
                let mut bare_options = ReferencesOptions::new();
                bare_options.kinds = Some(vec![ReferenceKind::Call]);
                bare_options.language = Some(language.as_str().to_string());
                bare_options.limit = Some(500);
                if let Ok(bare_refs) = find_references(bare, &project_root, &bare_options) {
                    let dot_pat = format!(".{}(", bare);
                    let space_pat = format!(".{} (", bare);
                    for r in &bare_refs.references {
                        // Filter: context must look like `<receiver>.<bare>(`
                        // — not a bare `bare(...)` call. Avoid promoting
                        // genuine homonym references on unrelated scopes.
                        if !r.context.contains(&dot_pat) && !r.context.contains(&space_pat) {
                            continue;
                        }
                        push_caller_from_reference(
                            report,
                            file,
                            function,
                            r,
                            &mut file_funcs_cache,
                        );
                    }
                }
            }
        }
    }
}

/// Helper used by both the primary references walk and the Lua bare-name
/// enrichment to convert a single `Reference` into a caller entry on
/// `report.callers`.
fn push_caller_from_reference(
    report: &mut ExplainReport,
    file: &std::path::Path,
    function: &str,
    r: &tldr_core::analysis::references::Reference,
    file_funcs_cache: &mut std::collections::HashMap<std::path::PathBuf, Vec<(String, u32, u32)>>,
) {
    let ref_path = &r.file;
    let funcs = file_funcs_cache
        .entry(ref_path.clone())
        .or_insert_with(|| collect_functions_with_bounds(ref_path));
    let enclosing = funcs
        .iter()
        .find(|(_, start, end)| {
            let line = r.line as u32;
            line >= *start && (*end == 0 || line <= *end)
        })
        .map(|(name, _, _)| name.clone());

    let caller_name = match enclosing {
        Some(n) => n,
        None => "<module>".to_string(),
    };
    let caller_file = ref_path.display().to_string();

    if explain_names_match(&caller_name, function) && paths_equivalent(ref_path, file) {
        return;
    }
    if caller_already_present(&report.callers, &caller_name, &caller_file) {
        return;
    }
    report
        .callers
        .push(CallInfo::new(caller_name, caller_file, r.line as u32));
}

/// critical-regressions-v1 (P13.AGG13-2): does `file` define a function whose
/// (bare or class-qualified) name matches `function`? Used by
/// `enrich_with_project_graph` to confirm a Swift extension's actual
/// owning file when impact's `tree.file` points at a sibling extension.
fn function_is_defined_in_file(
    file: &std::path::Path,
    function: &str,
    _language: Language,
) -> bool {
    let module = match tldr_core::extract_file(file, None) {
        Ok(m) => m,
        Err(_) => return false,
    };
    let target_tail = explain_last_segment(function);
    for f in &module.functions {
        if f.name == function || f.name == target_tail {
            return true;
        }
    }
    for class in &module.classes {
        for m in &class.methods {
            if m.name == function || m.name == target_tail {
                return true;
            }
            let qualified = format!("{}.{}", class.name, m.name);
            if qualified == function || explain_last_segment(&qualified) == target_tail {
                return true;
            }
        }
    }
    false
}

/// Collect `(function_name, line_start, line_end)` triples for every
/// top-level function and method in `file`. Returns an empty Vec if the
/// file fails to parse — callers tolerate this by attributing call
/// sites to `<module>`.
fn collect_functions_with_bounds(file: &std::path::Path) -> Vec<(String, u32, u32)> {
    let module = match tldr_core::extract_file(file, None) {
        Ok(m) => m,
        Err(_) => return Vec::new(),
    };
    let mut out: Vec<(String, u32, u32)> = Vec::new();
    for f in &module.functions {
        out.push((f.name.clone(), f.line_number, f.line_end));
    }
    for class in &module.classes {
        for m in &class.methods {
            // Index both the bare method name and the qualified Class.method
            // form so `find` can match either shape from the call-graph /
            // references emitter.
            out.push((m.name.clone(), m.line_number, m.line_end));
            out.push((
                format!("{}.{}", class.name, m.name),
                m.line_number,
                m.line_end,
            ));
        }
    }
    // Sort so the most-specific (innermost) function comes first when
    // multiple bounds contain the same line — by ascending line_start
    // descending end, but in practice find() returns first match so we
    // sort by descending line_start (innermost wins).
    out.sort_by(|a, b| b.1.cmp(&a.1));
    out
}

// =============================================================================
// Path-shape restoration (cross-cmd-path-shape-v1, v0.4.2 bug-A5)
// =============================================================================

/// Re-assert the user-supplied input path shape on every
/// `callers[].file` and `callees[].file` in a `ExplainReport`.
///
/// The audit (Phase-20, worker B-c-002) flagged that `tldr explain
/// /tmp/repos/.../IO.scala interpret` emits three different shapes for
/// the same file inside one response:
///   - top-level `file`: `/tmp/...` (verbatim user input — OK)
///   - `callers[]` from `enrich_with_project_graph`: project-relative
///     `core/.../SyncIO.scala` (the call-graph storage emits these)
///   - `callers[]` from `enrich_with_references`: canonicalised abs
///     `/private/tmp/.../SyncIO.scala` (find_references canonicalises)
///
/// The fix rewrites every emitted path to the user-input prefix
/// (`/tmp/repos/.../scala-cats-effect/...`). The rewrite has three
/// branches:
///   1. Path already starts with the user-input root  -> no rewrite.
///   2. Path starts with the canonical user-input root (macOS
///      `/private/tmp/...` form) -> rewrite the prefix back to the
///      user-input root.
///   3. Path is project-relative (`core/.../SyncIO.scala`) -> join it
///      with the user-input project root so the shape matches the
///      user-typed absolute prefix.
///
/// Mirrors the M3 (`5f6009e scala-path-canonical-v1`) and P15-B
/// (`6a3288a context-relative-and-ts-colon-v1`) precedent:
/// canonicalise for internal filter/match only, echo user input
/// verbatim in output.
fn restore_explain_path_shape(report: &mut super::types::ExplainReport, user_file: &std::path::Path) {
    // The user-supplied project root: walk up from `user_file` using
    // the same marker-based heuristic the rest of explain uses. This
    // produces the same `project_root` shape as
    // `explain_project_root`, but keyed against the user's INPUT
    // shape (not canonicalised) so the join produces a user-shaped
    // absolute path.
    let user_project_root = user_project_root_from_input(user_file);
    let canon_project_root = user_project_root
        .as_ref()
        .and_then(|p| dunce::canonicalize(p).ok());

    let rewrite = |s: &str| -> Option<String> {
        let p = std::path::Path::new(s);
        // 1. Already user-input-shaped? (starts with the user's
        //    project root). Leave alone.
        if let Some(root) = user_project_root.as_ref() {
            if p.starts_with(root) {
                return None;
            }
        }
        // 2. Canonical-prefix rewrite (macOS `/private/tmp/...`).
        if let (Some(canon), Some(root)) =
            (canon_project_root.as_ref(), user_project_root.as_ref())
        {
            if let Ok(suffix) = p.strip_prefix(canon) {
                if root.as_os_str().is_empty() {
                    return Some(suffix.display().to_string());
                }
                return Some(root.join(suffix).display().to_string());
            }
        }
        // 3. Project-relative -> absolutise against user project root.
        if p.is_relative() {
            if let Some(root) = user_project_root.as_ref() {
                return Some(root.join(p).display().to_string());
            }
        }
        None
    };

    for c in report.callers.iter_mut() {
        if let Some(np) = rewrite(&c.file) {
            c.file = np;
        }
    }
    for c in report.callees.iter_mut() {
        if let Some(np) = rewrite(&c.file) {
            c.file = np;
        }
    }
}

/// Walk upward from `user_file`'s parent directory (KEEPING the user's
/// input shape — no canonicalisation) until a project-root marker is
/// found. Mirrors `explain_project_root` but does not canonicalise the
/// path, so the returned root keeps the user-supplied prefix
/// (`/tmp/...`, `./repo/`, etc.).
fn user_project_root_from_input(user_file: &std::path::Path) -> Option<std::path::PathBuf> {
    let parent = user_file.parent()?;
    let markers = [
        "Cargo.toml",
        "package.json",
        "go.mod",
        "pyproject.toml",
        "setup.py",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        ".git",
    ];
    let mut cursor: Option<&std::path::Path> = Some(parent);
    while let Some(dir) = cursor {
        if dir.as_os_str().is_empty() {
            cursor = dir.parent();
            continue;
        }
        for m in &markers {
            if dir.join(m).exists() {
                return Some(dir.to_path_buf());
            }
        }
        cursor = dir.parent();
    }
    Some(parent.to_path_buf())
}

// =============================================================================
// Entry Point
// =============================================================================

impl ExplainArgs {
    /// Run the explain command
    pub fn run(&self, format: OutputFormat, quiet: bool) -> Result<()> {
        let writer = OutputWriter::new(format, quiet);

        writer.progress(&format!(
            "Analyzing function {} in {}...",
            self.function,
            self.file.display()
        ));

        // Check file exists
        if !self.file.exists() {
            return Err(RemainingError::file_not_found(&self.file).into());
        }

        // Detect language from file extension
        let language = Language::from_path(&self.file)
            .ok_or_else(|| RemainingError::parse_error(&self.file, "Unsupported language"))?;

        // Get function node kinds for this language
        let func_kinds = get_function_node_kinds(language);

        // Read source
        let source = std::fs::read_to_string(&self.file)
            .map_err(|e| RemainingError::parse_error(&self.file, e.to_string()))?;
        let source_bytes = source.as_bytes();

        // Parse with tree-sitter
        let mut parser = get_parser(language)?;
        let tree = parser
            .parse(&source, None)
            .ok_or_else(|| RemainingError::parse_error(&self.file, "Failed to parse file"))?;

        let root = tree.root_node();

        // Find the function. ux-and-explain-completeness-v1 (P12.AGG12-1):
        // delegate to the canonical `tldr_core::ast::function_finder::find_function_node`
        // first — it covers cross-language patterns (Lua/Luau dot-indexed
        // `function m.reset()`, JS arrow / object pair / assignment forms,
        // qualified `Class.method`, etc.) that the local explain walker
        // historically missed. Fall back to the local walker only on canonical
        // failure to preserve any pattern the canonical impl doesn't handle yet.
        let canonical_node = tldr_core::ast::function_finder::find_function_node(
            root,
            &self.function,
            language,
            &source,
        );
        let func_node = canonical_node
            .or_else(|| find_function_node(root, source_bytes, &self.function, func_kinds))
            .ok_or_else(|| RemainingError::symbol_not_found(&self.function, &self.file))?;

        // Get file path string
        let file_path = self.file.to_string_lossy().to_string();

        // Get language name for report
        let language_name = match language {
            Language::Python => "python",
            Language::TypeScript => "typescript",
            Language::JavaScript => "javascript",
            Language::Go => "go",
            Language::Rust => "rust",
            Language::Java => "java",
            Language::C => "c",
            Language::Cpp => "cpp",
            Language::CSharp => "csharp",
            Language::Kotlin => "kotlin",
            Language::Scala => "scala",
            Language::Php => "php",
            Language::Ruby => "ruby",
            Language::Lua => "lua",
            Language::Luau => "luau",
            Language::Elixir => "elixir",
            Language::Ocaml => "ocaml",
            Language::Swift => "swift",
        };

        // extract-slice-explain-decl-keyword-span-v1 (v0.4.2 M-002):
        // anchor `line_start` to the first non-modifier child of the
        // function node so annotation-decorated declarations
        // (java `@Override`, kotlin `@Deprecated`, scala `@deprecated`,
        // swift `@inlinable`) report the decl-keyword line, not the
        // leading annotation line. Matches the AST-walker normalisation
        // applied in `extract`/`slice` (CFG entry-block seed).
        let line_start = decl_keyword_line_from_node(&func_node);
        // Build report
        let mut report = ExplainReport::new(
            &self.function,
            &file_path,
            line_start,
            get_end_line_number(func_node),
            language_name,
        );

        // Extract signature
        report.signature = extract_signature(func_node, source_bytes, language);

        // Analyze purity
        report.purity = analyze_purity(func_node, source_bytes);

        // Compute complexity. Local walker fills `num_blocks`, `num_edges`,
        // and `has_loops`; cyclomatic is then overwritten with the canonical
        // value from `tldr_core::calculate_complexity` so `tldr explain` and
        // `tldr complexity` always agree (cross-command-consistency-v3
        // P5.BUG-N2). Falling back to the local cyclomatic only on canonical
        // failure preserves explain output for files that the canonical path
        // cannot find the function in (e.g. nested-class disambiguation
        // edge cases).
        let mut complexity_info = compute_complexity(func_node);
        if let Ok(canonical) = tldr_core::calculate_complexity(
            self.file.to_str().unwrap_or_default(),
            &self.function,
            language,
        ) {
            complexity_info.cyclomatic = canonical.cyclomatic;
        }
        // cpp-explain-refs-cleanup-v1 (BUG-CPP-P20-04): align
        // `complexity.num_blocks` with the canonical CFG block count so
        // `tldr explain` and `tldr context` never disagree on the same
        // function. The local `count_complexity_recursive` walker only
        // increments on Python-shaped node kinds (`if_statement` /
        // `for_statement` / `while_statement` / `try_statement` /
        // `except_clause`); a C++ function with `switch_statement`,
        // `case_statement`, `do_statement`, `goto_statement`, … was
        // therefore severely under-counted. The CFG builder handles
        // every supported language uniformly, so delegating mirrors the
        // cyclomatic alignment above.
        //
        // The lookup name is stripped of class prefix because
        // `get_cfg_context` matches by trailing identifier — same shape
        // as `get_cfg_metrics` in `tldr-core/src/context/builder.rs`.
        let lookup_name = self
            .function
            .rsplit("::")
            .next()
            .unwrap_or(&self.function);
        let lookup_name = lookup_name
            .rsplit('.')
            .next()
            .unwrap_or(lookup_name);
        if let Ok(cfg) = tldr_core::get_cfg_context(
            self.file.to_str().unwrap_or_default(),
            lookup_name,
            language,
        ) {
            if !cfg.blocks.is_empty() {
                complexity_info.num_blocks = cfg.blocks.len() as u32;
            }
        }
        // rust-explain-cognitive-v1 (v0.4.2 bug-C6 / VAL-RUST-EXPLAIN):
        // join `tldr cognitive`'s per-function value into explain's
        // complexity block so the two commands agree on the same
        // function. The audit flagged `complexity.cognitive: null` on
        // `tldr explain /tmp/repos/ripgrep/.../globset/src/glob.rs
        // parse` despite `tldr cognitive` reporting cog=19 for the
        // same function — the field never existed at all (partial
        // measurement artifact), but the underlying gap (explain's
        // complexity block missing the cognitive counterpart) is
        // real. Wiring is language-agnostic: every language the
        // cognitive analyzer supports gets populated. `None` on any
        // analysis error so the additive field never breaks consumers
        // that don't reference it.
        let cog_options = tldr_core::metrics::CognitiveOptions {
            function_filter: Some(self.function.clone()),
            threshold: tldr_core::metrics::cognitive::DEFAULT_THRESHOLD,
            high_threshold: tldr_core::metrics::cognitive::DEFAULT_HIGH_THRESHOLD,
            show_contributors: false,
            include_cyclomatic: false,
            // Match by name; the cognitive analyzer enumerates all
            // functions before filtering, so `top=0` (all) prevents
            // truncation when a same-named overload appears earlier.
            top: 0,
        };
        if let Ok(cog_report) = tldr_core::metrics::analyze_cognitive(&self.file, &cog_options) {
            // Prefer exact (name, line) match against the explain
            // target's start line; fall back to plain name match when
            // line ordering differs (e.g. lookup_name vs qualified
            // self.function). This handles same-named methods in
            // different impl blocks: explain has already resolved a
            // specific `func_node`, so its start line is canonical.
            let want_line = get_line_number(func_node);
            let by_line = cog_report
                .functions
                .iter()
                .find(|f| f.line == want_line && (f.name == self.function || f.name == lookup_name));
            let by_name = cog_report
                .functions
                .iter()
                .find(|f| f.name == self.function || f.name == lookup_name);
            if let Some(fc) = by_line.or(by_name) {
                complexity_info.cognitive = Some(fc.cognitive);
            }
        }
        report.complexity = Some(complexity_info);

        // Collect local function names for call graph analysis
        let local_functions = collect_function_names(root, source_bytes, func_kinds);

        // Find callees
        report.callees = find_callees(
            func_node,
            source_bytes,
            &file_path,
            &local_functions,
            language,
        );

        // Find callers
        report.callers = find_callers(root, source_bytes, &self.function, &file_path, func_kinds);

        // explain-cross-command-consistency-v1 (P11.BUG-AGG-1): the
        // per-file walker above only sees callers/callees defined in the
        // same source file. Enrich with cross-file results from the
        // project-wide call graph used by `tldr impact` /
        // `tldr references` / `tldr context` so the four commands agree
        // on relationships. Same-file results are preserved; only
        // additional cross-file edges get appended.
        enrich_with_project_graph(&mut report, &self.file, &self.function, language);

        // ux-and-explain-completeness-v1 (P12.AGG12-1): some languages
        // under-report call edges in the project call graph (e.g. C#,
        // Kotlin, Scala class-method invocations). For those, `tldr
        // references` still surfaces real call sites via text+AST
        // verification. Mirror that data source so explain's caller list
        // matches the "real" set users see from `tldr references`.
        // Path-aware dedup means same-file walker results and
        // call-graph results that already populated the list won't be
        // duplicated.
        enrich_with_references(&mut report, &self.file, &self.function, language);

        // cross-cmd-path-shape-v1 (v0.4.2 bug-A5): unify every
        // emitted `callers[].file` and `callees[].file` to the
        // user-supplied input shape. Three drift sources combine in a
        // single response:
        //   - `enrich_with_project_graph` emits project-relative
        //     (`core/.../X.scala`) from the call-graph storage.
        //   - `enrich_with_references` emits canonicalised absolute
        //     (`/private/tmp/.../X.scala`) from `find_references`.
        //   - The per-file walker emits `self.file.to_string_lossy()`
        //     (user input shape), agreeing with the top-level `file`.
        // The audit specifically flagged THREE shapes for the SAME
        // file in the same response. Rewriting every path to the
        // user-input prefix produces a homogeneous shape (M3 pattern).
        restore_explain_path_shape(&mut report, &self.file);

        // elixir-per-clause-dfg-cfg-v1 (v0.4.2 M-031): build a
        // per-clause summary for Elixir multi-clause `def` definitions.
        // Each clause runs a sub-analysis (CFG + complexity + cognitive)
        // on a synthetic single-clause sub-source. We attach the array
        // as a top-level `per_clauses` field on the explain JSON.
        let per_clause_array: Option<Vec<serde_json::Value>> = if writer.is_text() {
            None
        } else {
            let lookup_name_outer = self
                .function
                .rsplit("::")
                .next()
                .unwrap_or(&self.function)
                .rsplit('.')
                .next()
                .unwrap_or(&self.function)
                .to_string();
            let lookup_name = lookup_name_outer.clone();
            crate::commands::elixir_per_clause::for_each_body_bearing_clause(
                &self.file,
                &lookup_name_outer,
                language,
                move |tmp_path, clause, _offset| -> anyhow::Result<serde_json::Value> {
                    let mut entry = serde_json::Map::new();
                    if let Ok(cfg) = tldr_core::get_cfg_context(
                        tmp_path.to_str().unwrap_or_default(),
                        &lookup_name,
                        language,
                    ) {
                        entry.insert(
                            "num_blocks".to_string(),
                            serde_json::Value::from(cfg.blocks.len()),
                        );
                        entry.insert(
                            "num_edges".to_string(),
                            serde_json::Value::from(cfg.edges.len()),
                        );
                        entry.insert(
                            "cyclomatic".to_string(),
                            serde_json::Value::from(cfg.cyclomatic_complexity),
                        );
                    }
                    if let Ok(c) = tldr_core::calculate_complexity(
                        tmp_path.to_str().unwrap_or_default(),
                        &lookup_name,
                        language,
                    ) {
                        entry.insert(
                            "cognitive".to_string(),
                            serde_json::Value::from(c.cognitive),
                        );
                        entry.insert(
                            "lines_of_code".to_string(),
                            serde_json::Value::from(c.lines_of_code),
                        );
                        entry.insert(
                            "max_nesting".to_string(),
                            serde_json::Value::from(c.max_nesting),
                        );
                    }
                    Ok(crate::commands::elixir_per_clause::per_clause_entry_value(
                        clause,
                        serde_json::Value::Object(entry),
                    ))
                },
            )?
        };

        // Output based on format
        if writer.is_text() {
            let text = format_explain_text(&report);
            writer.write_text(&text)?;
        } else {
            let value = serde_json::to_value(&report)?;
            let merged = crate::commands::elixir_per_clause::merge_per_clauses(
                value,
                per_clause_array,
            );
            writer.write_text(&serde_json::to_string_pretty(&merged)?)?;
        }

        // Write to output file if specified
        if let Some(ref output_path) = self.output {
            let output_str = if format == OutputFormat::Text {
                format_explain_text(&report)
            } else {
                serde_json::to_string_pretty(&report)?
            };
            std::fs::write(output_path, &output_str)?;
        }

        Ok(())
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_CODE: &str = r#"
def calculate_total(items: list[dict], tax_rate: float = 0.1) -> float:
    """Calculate total price with tax.

    Args:
        items: List of items with 'price' key
        tax_rate: Tax rate as decimal (default 10%)

    Returns:
        Total price including tax
    """
    subtotal = sum(item['price'] for item in items)
    return subtotal * (1 + tax_rate)

def helper_function(x):
    return x * 2

def main():
    items = [{'price': 10}, {'price': 20}]
    total = calculate_total(items)
    doubled = helper_function(total)
    print(doubled)
"#;

    #[test]
    fn test_find_function() {
        let language = Language::Python;
        let func_kinds = get_function_node_kinds(language);
        let mut parser = get_parser(language).unwrap();
        let tree = parser.parse(SAMPLE_CODE, None).unwrap();
        let root = tree.root_node();

        let func = find_function_node(root, SAMPLE_CODE.as_bytes(), "calculate_total", func_kinds);
        assert!(func.is_some());

        let func = find_function_node(root, SAMPLE_CODE.as_bytes(), "nonexistent", func_kinds);
        assert!(func.is_none());
    }

    #[test]
    fn test_extract_signature() {
        let language = Language::Python;
        let func_kinds = get_function_node_kinds(language);
        let mut parser = get_parser(language).unwrap();
        let tree = parser.parse(SAMPLE_CODE, None).unwrap();
        let root = tree.root_node();

        let func = find_function_node(root, SAMPLE_CODE.as_bytes(), "calculate_total", func_kinds)
            .unwrap();
        let sig = extract_signature(func, SAMPLE_CODE.as_bytes(), language);

        assert_eq!(sig.params.len(), 2);
        assert_eq!(sig.params[0].name, "items");
        assert_eq!(sig.params[1].name, "tax_rate");
        assert!(sig.return_type.is_some());
        assert!(sig.docstring.is_some());
    }

    #[test]
    fn test_purity_analysis() {
        let language = Language::Python;
        let func_kinds = get_function_node_kinds(language);
        let mut parser = get_parser(language).unwrap();
        let tree = parser.parse(SAMPLE_CODE, None).unwrap();
        let root = tree.root_node();

        // calculate_total should be pure
        let func = find_function_node(root, SAMPLE_CODE.as_bytes(), "calculate_total", func_kinds)
            .unwrap();
        let purity = analyze_purity(func, SAMPLE_CODE.as_bytes());
        assert_eq!(purity.classification, "pure");

        // main calls print, so impure
        let func = find_function_node(root, SAMPLE_CODE.as_bytes(), "main", func_kinds).unwrap();
        let purity = analyze_purity(func, SAMPLE_CODE.as_bytes());
        assert_eq!(purity.classification, "impure");
        assert!(purity.effects.contains(&"io".to_string()));
    }

    #[test]
    fn test_complexity_analysis() {
        let code = r#"
def complex_func(x, y):
    if x > 0:
        if y > 0:
            return x + y
        else:
            return x
    else:
        for i in range(10):
            x += i
        return x
"#;
        let language = Language::Python;
        let func_kinds = get_function_node_kinds(language);
        let mut parser = get_parser(language).unwrap();
        let tree = parser.parse(code, None).unwrap();
        let root = tree.root_node();

        let func = find_function_node(root, code.as_bytes(), "complex_func", func_kinds).unwrap();
        let cx = compute_complexity(func);

        assert!(cx.cyclomatic > 1);
        assert!(cx.has_loops);
    }

    #[test]
    fn test_find_callees() {
        let language = Language::Python;
        let func_kinds = get_function_node_kinds(language);
        let mut parser = get_parser(language).unwrap();
        let tree = parser.parse(SAMPLE_CODE, None).unwrap();
        let root = tree.root_node();

        let local_funcs = collect_function_names(root, SAMPLE_CODE.as_bytes(), func_kinds);
        let func = find_function_node(root, SAMPLE_CODE.as_bytes(), "main", func_kinds).unwrap();
        let callees = find_callees(
            func,
            SAMPLE_CODE.as_bytes(),
            "test.py",
            &local_funcs,
            language,
        );

        assert!(callees.iter().any(|c| c.name == "calculate_total"));
        assert!(callees.iter().any(|c| c.name == "helper_function"));
    }

    #[test]
    fn test_find_callers() {
        let language = Language::Python;
        let func_kinds = get_function_node_kinds(language);
        let mut parser = get_parser(language).unwrap();
        let tree = parser.parse(SAMPLE_CODE, None).unwrap();
        let root = tree.root_node();

        let callers = find_callers(
            root,
            SAMPLE_CODE.as_bytes(),
            "calculate_total",
            "test.py",
            func_kinds,
        );
        assert!(callers.iter().any(|c| c.name == "main"));
    }

    #[test]
    fn test_find_ts_arrow_function() {
        let ts_source = r#"
const getDuration = (start: Date, end: Date): number => {
    return end.getTime() - start.getTime();
};

function regularFunc(x: number): number {
    return x * 2;
}

export const processItems = (items: string[]) => {
    return items.map(i => i.trim());
};
"#;
        let language = Language::TypeScript;
        let func_kinds = get_function_node_kinds(language);
        let mut parser = get_parser(language).unwrap();
        let tree = parser.parse(ts_source, None).unwrap();
        let root = tree.root_node();

        // Regular function should always work
        let regular = find_function_node(root, ts_source.as_bytes(), "regularFunc", func_kinds);
        assert!(regular.is_some(), "Should find regular TS function");

        // Arrow function assigned to const should also work
        let arrow = find_function_node(root, ts_source.as_bytes(), "getDuration", func_kinds);
        assert!(
            arrow.is_some(),
            "Should find TS arrow function 'getDuration'"
        );

        // Exported arrow function should also work
        let exported = find_function_node(root, ts_source.as_bytes(), "processItems", func_kinds);
        assert!(
            exported.is_some(),
            "Should find exported TS arrow function 'processItems'"
        );
    }

    // =========================================================================
    // Bug: analyze_purity returns "pure" when it should return "unknown"
    // =========================================================================

    /// A function with no function body content (empty/pass) should classify
    /// as "unknown", not "pure". We have no evidence of purity -- the analysis
    /// simply found nothing.
    #[test]
    fn test_empty_function_is_unknown_not_pure() {
        let source = r#"
def empty_func():
    pass
"#;
        let language = Language::Python;
        let func_kinds = get_function_node_kinds(language);
        let mut parser = get_parser(language).unwrap();
        let tree = parser.parse(source, None).unwrap();
        let root = tree.root_node();

        let func_node = find_function_node(root, source.as_bytes(), "empty_func", func_kinds);
        assert!(func_node.is_some(), "Should find empty_func");

        let purity = analyze_purity(func_node.unwrap(), source.as_bytes());

        // The buggy code returns "pure" because no effects and no unknown calls.
        // But "pass" means we found nothing -- not that we proved purity.
        // A truly empty function (just `pass`) has no evidence to support "pure".
        assert_ne!(
            purity.classification, "pure",
            "A function with only `pass` (no calls, no computation) should NOT be classified as \
             'pure' with high confidence. We have no evidence to support a purity claim. \
             Got classification='{}', confidence='{}'. Expected 'unknown'.",
            purity.classification, purity.confidence
        );
    }

    /// A function that calls other user-defined functions (not builtins, not IO)
    /// where those calls are unresolved should classify as "unknown", not "pure".
    ///
    /// The bug: when a call doesn't match IO_OPERATIONS, IMPURE_CALLS,
    /// COLLECTION_MUTATIONS, or PURE_BUILTINS, it sets has_unknown_calls=true.
    /// This case is actually handled correctly for unknown calls, BUT if the
    /// call name happens to match a PURE_BUILTIN substring, it incorrectly
    /// passes as pure. This test verifies the general "unknown calls" path works.
    #[test]
    fn test_function_with_unknown_calls_is_unknown() {
        let source = r#"
def my_func(x):
    result = compute_something(x)
    return transform_result(result)
"#;
        let language = Language::Python;
        let func_kinds = get_function_node_kinds(language);
        let mut parser = get_parser(language).unwrap();
        let tree = parser.parse(source, None).unwrap();
        let root = tree.root_node();

        let func_node = find_function_node(root, source.as_bytes(), "my_func", func_kinds);
        assert!(func_node.is_some(), "Should find my_func");

        let purity = analyze_purity(func_node.unwrap(), source.as_bytes());

        // compute_something and transform_result are NOT in PURE_BUILTINS,
        // so has_unknown_calls should be true -> classification = "unknown"
        assert_eq!(
            purity.classification, "unknown",
            "Function calling unknown user functions should be 'unknown', got '{}'",
            purity.classification
        );
        assert_ne!(
            purity.confidence, "high",
            "Unknown classification should not have high confidence, got '{}'",
            purity.confidence
        );
    }

    /// A function that ONLY calls known-pure builtins should classify as "pure".
    /// This is the legitimate pure case.
    #[test]
    fn test_only_pure_builtins_is_pure() {
        let source = r#"
def pure_func(items):
    return len(items) + sum(items)
"#;
        let language = Language::Python;
        let func_kinds = get_function_node_kinds(language);
        let mut parser = get_parser(language).unwrap();
        let tree = parser.parse(source, None).unwrap();
        let root = tree.root_node();

        let func_node = find_function_node(root, source.as_bytes(), "pure_func", func_kinds);
        assert!(func_node.is_some(), "Should find pure_func");

        let purity = analyze_purity(func_node.unwrap(), source.as_bytes());

        assert_eq!(
            purity.classification, "pure",
            "Function calling only pure builtins (len, sum) should be 'pure', got '{}'",
            purity.classification
        );
        assert_eq!(
            purity.confidence, "high",
            "Pure classification should have high confidence"
        );
    }

    /// A function with IO operations should classify as "impure".
    #[test]
    fn test_io_operations_is_impure() {
        let source = r#"
def impure_func(msg):
    print(msg)
    return True
"#;
        let language = Language::Python;
        let func_kinds = get_function_node_kinds(language);
        let mut parser = get_parser(language).unwrap();
        let tree = parser.parse(source, None).unwrap();
        let root = tree.root_node();

        let func_node = find_function_node(root, source.as_bytes(), "impure_func", func_kinds);
        assert!(func_node.is_some(), "Should find impure_func");

        let purity = analyze_purity(func_node.unwrap(), source.as_bytes());

        assert_eq!(
            purity.classification, "impure",
            "Function with print() should be 'impure', got '{}'",
            purity.classification
        );
        assert_eq!(
            purity.confidence, "high",
            "Impure classification should have high confidence"
        );
        assert!(
            purity.effects.contains(&"io".to_string()),
            "Effects should contain 'io', got {:?}",
            purity.effects
        );
    }

    /// A function with only arithmetic (no calls at all) should be "unknown"
    /// because we have no positive evidence of purity -- the analysis simply
    /// didn't find any calls to classify.
    #[test]
    fn test_no_calls_arithmetic_only_is_unknown() {
        let source = r#"
def add(a, b):
    return a + b
"#;
        let language = Language::Python;
        let func_kinds = get_function_node_kinds(language);
        let mut parser = get_parser(language).unwrap();
        let tree = parser.parse(source, None).unwrap();
        let root = tree.root_node();

        let func_node = find_function_node(root, source.as_bytes(), "add", func_kinds);
        assert!(func_node.is_some(), "Should find add");

        let purity = analyze_purity(func_node.unwrap(), source.as_bytes());

        // The bug: analyze_purity returns "pure" because no effects and
        // no unknown calls. But we have no positive evidence -- we just
        // didn't find any calls. The correct answer is "unknown" with
        // low confidence, or at minimum not "pure/high".
        assert_ne!(
            purity.classification, "pure",
            "A simple arithmetic function with no calls should NOT confidently be 'pure'. \
             The analysis found no calls to evaluate -- absence of evidence is not evidence \
             of purity. Got classification='{}', confidence='{}'. \
             Expected 'unknown' since no calls were analyzed.",
            purity.classification, purity.confidence
        );
    }
}
