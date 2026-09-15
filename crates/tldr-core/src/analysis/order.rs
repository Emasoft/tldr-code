//! Definition-order analysis (issue #8b) — use-before-define / TDZ report.
//!
//! Motivating repro (issue #8): an edit referenced `let dataFetchSeq = 0;`
//! declared ~170 lines AFTER the edited function. `tldr impact` passed but
//! eslint failed with 4x `no-use-before-define`. Every fact needed to catch
//! this is already in a parsed tree — the definition's line range was already
//! visible in `tldr structure` output — so this pass computes the report
//! directly from a tree-sitter parse, no call graph required.
//!
//! # Semantics (MVP)
//!
//! ## JavaScript / TypeScript
//!
//! 1. Collect **module-scope** declarations in source order:
//!    `let`/`const` ([`lexical_declaration`]), `var` ([`variable_declaration`]),
//!    `function` declarations and `class` declarations — including the
//!    `export`-prefixed and decorator-wrapped spellings.
//! 2. Collect identifier references to those names **anywhere in the file**
//!    (references inside any function count — that is exactly the issue #8
//!    shape: a function body referencing a later module-level `let`).
//! 3. Flag a reference whose line is STRICTLY BEFORE the declaration line for
//!    the TDZ kinds `let` / `const` / `class`. `function` declarations and
//!    `var` are hoisted, so they are TDZ-safe and never flagged (but they DO
//!    count toward `checked_definitions`).
//!
//! Property accesses (`obj.x` → `property_identifier`), shorthand object
//! values, destructuring-binding positions and parameter names are not value
//! reads and are excluded. A reference that is shadowed by a nested
//! declaration of the same name (function params, inner `let`, loop
//! declarations, catch params) is conservatively NOT flagged.
//!
//! ## Python
//!
//! Conservative module-level check (pylint `used-before-assignment` style):
//! collect module-level `def` / `class` / assignment bindings, then flag a
//! module-level NAME **read** that occurs before the binding line of that
//! name. Reads inside functions/lambdas/comprehensions are not considered
//! (Python resolves them at call time), and writes (assignment/loop targets,
//! parameters, import bindings, `with ... as` targets, attribute and keyword
//! names) are not reads. A `def` called at the bottom after all defs is
//! clean; a module-level read of a name assigned later is flagged.
//!
//! # Language coverage
//!
//! JavaScript, TypeScript and Python are analyzed. For every other language
//! the report carries `explanation = Some("definition-order analysis not yet
//! supported for <lang>")` with zero issues (graceful degradation, cf. #10).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use tree_sitter::Node;

use crate::ast::parser::parse;
use crate::types::Language;

/// One use-before-define hazard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderIssue {
    /// Name referenced before it was defined.
    pub symbol: String,
    /// Kind of the definition: `"let"` | `"const"` | `"class"` | `"var"` |
    /// `"assignment"` | `"function"`. Only TDZ kinds (`let`/`const`/`class`
    /// for JS/TS; every kind for module-level Python) are ever flagged.
    pub kind: String,
    /// 1-indexed line of the offending reference.
    pub use_line: u32,
    /// 1-indexed line of the definition it precedes.
    pub definition_line: u32,
    /// The trimmed source text of the use line.
    pub snippet: String,
}

/// Definition-order report for a single file.
///
/// Schema tag: `order-command-v1 (issue #8)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderReport {
    /// Analyzed file. Empty for the source-string core entry point; the CLI
    /// fills it from the resolved path (the core signature takes only the
    /// source text, so the label is the caller's concern).
    pub file: String,
    /// Language label (e.g. `"javascript"`, `"python"`).
    pub language: String,
    /// Hazards in source order of the offending use.
    pub issues: Vec<OrderIssue>,
    /// Number of module-scope declarations examined.
    pub checked_definitions: u32,
    /// Set when the language is out of MVP scope (or the source could not be
    /// parsed) so consumers can distinguish "clean" from "not analyzed".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub explanation: Option<String>,
}

/// A module-scope (or module-level Python) declaration discovered in the file.
#[derive(Debug, Clone)]
struct ModuleDeclaration {
    name: String,
    kind: &'static str,
    line: u32,
}

/// Analyze `source` for use-before-define / TDZ hazards.
///
/// MVP scope: [`Language::JavaScript`], [`Language::TypeScript`] and
/// [`Language::Python`]. Unsupported languages yield a report with an
/// `explanation` and zero issues.
pub fn analyze_definition_order(source: &str, language: Language) -> OrderReport {
    match language {
        Language::JavaScript | Language::TypeScript => analyze_js_like(source, language),
        Language::Python => analyze_python(source, language),
        other => OrderReport {
            file: String::new(),
            language: other.as_str().to_string(),
            issues: Vec::new(),
            checked_definitions: 0,
            explanation: Some(format!(
                "definition-order analysis not yet supported for {}",
                other.as_str()
            )),
        },
    }
}

// -----------------------------------------------------------------------------
// Shared helpers
// -----------------------------------------------------------------------------

/// 1-indexed start line of `node`.
fn line_of(node: Node) -> u32 {
    node.start_position().row as u32 + 1
}

/// Trimmed text of the 1-indexed `line`.
fn line_text(source: &str, line: u32) -> String {
    source
        .lines()
        .nth(line.saturating_sub(1) as usize)
        .unwrap_or("")
        .trim()
        .to_string()
}

/// Visit every node of the subtree rooted at `root` in document (preorder)
/// order.
fn for_each_node<'tree, F: FnMut(Node<'tree>)>(root: Node<'tree>, visit: &mut F) {
    let mut cursor = root.walk();
    loop {
        visit(cursor.node());
        if cursor.goto_first_child() {
            continue;
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                return;
            }
        }
    }
}

fn empty_report(language: Language) -> OrderReport {
    OrderReport {
        file: String::new(),
        language: language.as_str().to_string(),
        issues: Vec::new(),
        checked_definitions: 0,
        explanation: None,
    }
}

fn parse_failed_report(language: Language, message: String) -> OrderReport {
    OrderReport {
        explanation: Some(message),
        ..empty_report(language)
    }
}

// -----------------------------------------------------------------------------
// JavaScript / TypeScript
// -----------------------------------------------------------------------------

/// Node kinds that introduce a function scope in the JS/TS grammar.
const JS_FUNCTION_KINDS: &[&str] = &[
    "function_declaration",
    "generator_function_declaration",
    "function_expression",
    "generator_function",
    "arrow_function",
    "method_definition",
];

/// JS/TS analysis: module-scope declarations vs. any identifier reference.
fn analyze_js_like(source: &str, language: Language) -> OrderReport {
    let tree = match parse(source, language) {
        Ok(t) => t,
        Err(e) => {
            return parse_failed_report(
                language,
                format!(
                    "definition-order analysis could not parse the source: {}",
                    e
                ),
            )
        }
    };
    let root = tree.root_node();
    let bytes = source.as_bytes();

    // 1. Module-scope declarations, in source order.
    let mut declarations: Vec<ModuleDeclaration> = Vec::new();
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        match child.kind() {
            // `export const x = 1;` / `export function f() {}` / ...
            "export_statement" => {
                let mut ec = child.walk();
                for inner in child.children(&mut ec) {
                    js_extract_declarations(inner, bytes, &mut declarations);
                }
            }
            // `@dec class Foo {}` (TS decorated definitions)
            "decorated_definition" => {
                let mut dc = child.walk();
                for inner in child.children(&mut dc) {
                    js_extract_declarations(inner, bytes, &mut declarations);
                }
            }
            _ => js_extract_declarations(child, bytes, &mut declarations),
        }
    }
    let checked_definitions = declarations.len() as u32;

    // First module-scope declaration wins for duplicated names.
    let mut by_name: HashMap<&str, &ModuleDeclaration> = HashMap::new();
    for decl in &declarations {
        by_name.entry(decl.name.as_str()).or_insert(decl);
    }

    // 2. Identifier references anywhere in the file.
    let mut issues: Vec<OrderIssue> = Vec::new();
    for_each_node(root, &mut |node| {
        if node.kind() != "identifier" || js_is_binding_position(node) {
            return;
        }
        let name = match node.utf8_text(bytes) {
            Ok(t) => t,
            Err(_) => return,
        };
        let decl = match by_name.get(name) {
            Some(d) => *d,
            None => return,
        };
        // `var` and `function` are hoisted — TDZ-safe, never flagged.
        if !matches!(decl.kind, "let" | "const" | "class") {
            return;
        }
        let use_line = line_of(node);
        if use_line >= decl.line {
            return;
        }
        if js_is_shadowed(node.parent(), name, bytes) {
            return;
        }
        issues.push(OrderIssue {
            symbol: name.to_string(),
            kind: decl.kind.to_string(),
            use_line,
            definition_line: decl.line,
            snippet: line_text(source, use_line),
        });
    });

    OrderReport {
        file: String::new(),
        language: language.as_str().to_string(),
        issues,
        checked_definitions,
        explanation: None,
    }
}

/// Extract module-scope declarations from a single top-level statement.
fn js_extract_declarations(stmt: Node, source: &[u8], out: &mut Vec<ModuleDeclaration>) {
    let line = line_of(stmt);
    match stmt.kind() {
        "lexical_declaration" | "variable_declaration" => {
            // The first (anonymous) child is the `let` / `const` / `var` keyword.
            let mut keyword = "var";
            let mut cursor = stmt.walk();
            for child in stmt.children(&mut cursor) {
                if matches!(child.kind(), "let" | "const" | "var") {
                    keyword = child.kind();
                    break;
                }
            }
            let mut cursor = stmt.walk();
            for child in stmt.children(&mut cursor) {
                if child.kind() != "variable_declarator" {
                    continue;
                }
                // Destructuring declarators (`let {a} = x`) are not tracked —
                // conservative: only simple identifier bindings count.
                if let Some(name) = child.child_by_field_name("name") {
                    if name.kind() == "identifier" {
                        if let Ok(text) = name.utf8_text(source) {
                            out.push(ModuleDeclaration {
                                name: text.to_string(),
                                kind: keyword,
                                line,
                            });
                        }
                    }
                }
            }
        }
        "function_declaration" | "generator_function_declaration" => {
            if let Some(name) = stmt.child_by_field_name("name") {
                if let Ok(text) = name.utf8_text(source) {
                    out.push(ModuleDeclaration {
                        name: text.to_string(),
                        kind: "function",
                        line,
                    });
                }
            }
        }
        "class_declaration" | "abstract_class_declaration" => {
            // TS grammar names classes with `type_identifier`.
            if let Some(name) = stmt.child_by_field_name("name") {
                if let Ok(text) = name.utf8_text(source) {
                    out.push(ModuleDeclaration {
                        name: text.to_string(),
                        kind: "class",
                        line,
                    });
                }
            }
        }
        _ => {}
    }
}

/// True when `node` is a binding/declaration position rather than a value
/// read: declaration names, parameter lists, destructuring patterns, import
/// internals, and for-loop write targets.
fn js_is_binding_position(node: Node) -> bool {
    if let Some(parent) = node.parent() {
        match parent.kind() {
            // The `name` field of these containers is a declaration, not a use.
            "variable_declarator"
            | "function_declaration"
            | "generator_function_declaration"
            | "function_expression"
            | "generator_function"
            | "class_declaration"
            | "abstract_class_declaration" => {
                if let Some(name) = parent.child_by_field_name("name") {
                    if name.id() == node.id() {
                        return true;
                    }
                }
            }
            // Single-parameter arrow functions bind directly: `x => x`.
            "arrow_function" => {
                if let Some(params) = parent.child_by_field_name("parameters") {
                    if params.id() == node.id() {
                        return true;
                    }
                }
            }
            // `for (x in obj)` / `for (x of it)` write targets.
            "for_in_statement" | "for_statement" => {
                if let Some(left) = parent.child_by_field_name("left") {
                    if left.id() == node.id() {
                        return true;
                    }
                }
            }
            _ => {}
        }
    }

    // Anything nested inside parameter lists, destructuring patterns or
    // import internals is a binding (or conservatively treated as one —
    // e.g. parameter default values).
    let mut ancestor = node.parent();
    while let Some(a) = ancestor {
        if matches!(
            a.kind(),
            "formal_parameters"
                | "required_parameter"
                | "optional_parameter"
                | "object_pattern"
                | "array_pattern"
                | "import_statement"
                | "import_clause"
                | "named_imports"
                | "namespace_import"
                | "import_specifier"
        ) {
            return true;
        }
        ancestor = a.parent();
    }
    false
}

/// True when the reference is shadowed by a declaration of `name` in any
/// nested scope between it and module scope (module scope itself is where the
/// tracked declarations live, so it is excluded from the walk).
fn js_is_shadowed(start: Option<Node>, name: &str, source: &[u8]) -> bool {
    let mut ancestor = start;
    while let Some(a) = ancestor {
        if a.kind() == "program" {
            break;
        }
        if js_node_directly_declares(a, name, source) {
            return true;
        }
        // Parameters of an enclosing function shadow everything inside it.
        if JS_FUNCTION_KINDS.contains(&a.kind()) {
            if let Some(params) = a.child_by_field_name("parameters") {
                if js_subtree_has_identifier(params, name, source) {
                    return true;
                }
            }
        }
        ancestor = a.parent();
    }
    false
}

/// True when a direct child of `container` declares `name`.
fn js_node_directly_declares(container: Node, name: &str, source: &[u8]) -> bool {
    let mut cursor = container.walk();
    for child in container.children(&mut cursor) {
        match child.kind() {
            "lexical_declaration" | "variable_declaration" => {
                let mut dc = child.walk();
                for declarator in child.children(&mut dc) {
                    if declarator.kind() != "variable_declarator" {
                        continue;
                    }
                    if let Some(n) = declarator.child_by_field_name("name") {
                        if n.utf8_text(source) == Ok(name) {
                            return true;
                        }
                    }
                }
            }
            "function_declaration"
            | "generator_function_declaration"
            | "function_expression"
            | "generator_function"
            | "class_declaration"
            | "abstract_class_declaration" => {
                if let Some(n) = child.child_by_field_name("name") {
                    if n.utf8_text(source) == Ok(name) {
                        return true;
                    }
                }
            }
            _ => {}
        }
    }
    false
}

/// True when any `identifier` in the subtree rooted at `node` is named `name`.
fn js_subtree_has_identifier(node: Node, name: &str, source: &[u8]) -> bool {
    let mut found = false;
    for_each_node(node, &mut |n| {
        if !found && n.kind() == "identifier" {
            if let Ok(t) = n.utf8_text(source) {
                if t == name {
                    found = true;
                }
            }
        }
    });
    found
}

// -----------------------------------------------------------------------------
// Python
// -----------------------------------------------------------------------------

/// Python analysis: module-level bindings vs. module-level reads.
///
/// Conservative by design — see the module docs. Reads inside functions,
/// lambdas and comprehensions are never considered, which keeps false
/// positives at zero for the cost of missing call-time use-before-bind cases.
fn analyze_python(source: &str, language: Language) -> OrderReport {
    let tree = match parse(source, language) {
        Ok(t) => t,
        Err(e) => {
            return parse_failed_report(
                language,
                format!(
                    "definition-order analysis could not parse the source: {}",
                    e
                ),
            )
        }
    };
    let root = tree.root_node();
    let bytes = source.as_bytes();

    // 1. Module-level bindings: direct children of the `module` node.
    let mut declarations: Vec<ModuleDeclaration> = Vec::new();
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        match child.kind() {
            "function_definition" => {
                if let Some(name) = child.child_by_field_name("name") {
                    if let Ok(text) = name.utf8_text(bytes) {
                        declarations.push(ModuleDeclaration {
                            name: text.to_string(),
                            kind: "function",
                            line: line_of(child),
                        });
                    }
                }
            }
            "class_definition" => {
                if let Some(name) = child.child_by_field_name("name") {
                    if let Ok(text) = name.utf8_text(bytes) {
                        declarations.push(ModuleDeclaration {
                            name: text.to_string(),
                            kind: "class",
                            line: line_of(child),
                        });
                    }
                }
            }
            // `x = 1` / `x: int = 0` are wrapped in an expression_statement.
            "expression_statement" => {
                let mut ec = child.walk();
                for inner in child.children(&mut ec) {
                    if inner.kind() != "assignment" {
                        continue;
                    }
                    if let Some(left) = inner.child_by_field_name("left") {
                        py_collect_binding_names(left, bytes, line_of(inner), &mut declarations);
                    }
                }
            }
            _ => {}
        }
    }
    let checked_definitions = declarations.len() as u32;

    // First module-level binding wins for duplicated names.
    let mut by_name: HashMap<&str, &ModuleDeclaration> = HashMap::new();
    for decl in &declarations {
        by_name.entry(decl.name.as_str()).or_insert(decl);
    }

    // 2. Module-level reads.
    let mut issues: Vec<OrderIssue> = Vec::new();
    for_each_node(root, &mut |node| {
        if node.kind() != "identifier" {
            return;
        }
        if py_is_non_read(node) {
            return;
        }
        if py_inside_function_or_subscope(node) {
            return;
        }
        let name = match node.utf8_text(bytes) {
            Ok(t) => t,
            Err(_) => return,
        };
        let decl = match by_name.get(name) {
            Some(d) => *d,
            None => return,
        };
        let use_line = line_of(node);
        if use_line >= decl.line {
            return;
        }
        issues.push(OrderIssue {
            symbol: name.to_string(),
            kind: decl.kind.to_string(),
            use_line,
            definition_line: decl.line,
            snippet: line_text(source, use_line),
        });
    });

    OrderReport {
        file: String::new(),
        language: language.as_str().to_string(),
        issues,
        checked_definitions,
        explanation: None,
    }
}

/// Collect binding names from an assignment LHS at module level. Only simple
/// identifiers and destructuring pattern containers are tracked; attribute
/// and subscript targets (`d["k"] = 1`) are writes to other objects, not
/// module bindings.
fn py_collect_binding_names(lhs: Node, source: &[u8], line: u32, out: &mut Vec<ModuleDeclaration>) {
    match lhs.kind() {
        "identifier" => {
            if let Ok(text) = lhs.utf8_text(source) {
                out.push(ModuleDeclaration {
                    name: text.to_string(),
                    kind: "assignment",
                    line,
                });
            }
        }
        "pattern_list" | "tuple" | "list" => {
            let mut cursor = lhs.walk();
            for child in lhs.children(&mut cursor) {
                py_collect_binding_names(child, source, line, out);
            }
        }
        _ => {}
    }
}

/// True when `node` is a write/binding position (or another non-read like an
/// attribute access or a keyword-argument name) rather than a value read.
fn py_is_non_read(node: Node) -> bool {
    let parent = match node.parent() {
        Some(p) => p,
        None => return true,
    };
    match parent.kind() {
        // `def f(...)` / `class C(...)` declaration names.
        "function_definition" | "class_definition" => parent
            .child_by_field_name("name")
            .map(|n| n.id() == node.id())
            .unwrap_or(false),
        // Assignment and augmented-assignment targets are writes.
        "assignment" | "augmented_assignment" => parent
            .child_by_field_name("left")
            .map(|n| n.id() == node.id())
            .unwrap_or(false),
        // `for x in ...` loop targets are writes.
        "for_statement" | "for_in_clause" => parent
            .child_by_field_name("left")
            .map(|n| n.id() == node.id())
            .unwrap_or(false),
        // Walrus assignments bind their name.
        "named_expression" => parent
            .child_by_field_name("name")
            .map(|n| n.id() == node.id())
            .unwrap_or(false),
        // `obj.attr` — `attr` is a property access, not a variable read.
        "attribute" => parent
            .child_by_field_name("attribute")
            .map(|n| n.id() == node.id())
            .unwrap_or(false),
        // `f(x=1)` — the keyword name is not a variable read.
        "keyword_argument" => parent
            .child_by_field_name("name")
            .map(|n| n.id() == node.id())
            .unwrap_or(false),
        // Positional parameter names are bindings.
        "parameters" | "typed_parameter" => true,
        // Default/typed parameters: the name is a binding, but the default
        // VALUE is a real read — only skip the name.
        "default_parameter" | "typed_default_parameter" => parent
            .child_by_field_name("name")
            .map(|n| n.id() == node.id())
            .unwrap_or(false),
        // Import machinery, `global`/`nonlocal`/`del` statements.
        "import_statement"
        | "import_from_statement"
        | "dotted_name"
        | "aliased_import"
        | "relative_import"
        | "wildcard_import"
        | "global_statement"
        | "nonlocal_statement"
        | "delete_statement" => true,
        // `with <context> as <target>`: the trailing target is a binding.
        "with_item" => {
            let count = parent.child_count();
            count >= 3 && parent.child(count - 1).map(|c| c.id()) == Some(node.id())
        }
        _ => false,
    }
}

/// True when `node` sits inside a scope Python resolves at call time
/// (function body/params, lambda) or inside a comprehension's implicit
/// sub-scope — conservatively excluded from module-level read detection.
fn py_inside_function_or_subscope(node: Node) -> bool {
    let mut ancestor = node.parent();
    while let Some(a) = ancestor {
        if matches!(
            a.kind(),
            "function_definition"
                | "lambda"
                | "list_comprehension"
                | "set_comprehension"
                | "dictionary_comprehension"
                | "generator_expression"
        ) {
            return true;
        }
        ancestor = a.parent();
    }
    false
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // (a) THE issue #8 repro: a function references a module-level `let`
    // declared long after it.
    #[test]
    fn js_function_referencing_later_let_is_flagged() {
        let source = "\
function edit() {
  return dataFetchSeq;
}

let dataFetchSeq = 0;
";
        let report = analyze_definition_order(source, Language::JavaScript);
        assert_eq!(report.language, "javascript");
        assert!(report.explanation.is_none());
        assert_eq!(report.checked_definitions, 2, "function + let");
        assert_eq!(report.issues.len(), 1, "issues: {:?}", report.issues);
        let issue = &report.issues[0];
        assert_eq!(issue.symbol, "dataFetchSeq");
        assert_eq!(issue.kind, "let");
        assert_eq!(issue.use_line, 2);
        assert_eq!(
            issue.definition_line, 5,
            "let is on the 5th line (blank line 4)"
        );
        assert!(issue.use_line < issue.definition_line);
        assert_eq!(issue.snippet, "return dataFetchSeq;");
    }

    // (a') exports and a real ~170-line gap still get caught.
    #[test]
    fn js_exported_let_far_below_is_flagged() {
        let mut source = String::from("function edit() {\n  return dataFetchSeq;\n}\n");
        for i in 0..170 {
            source.push_str(&format!("// padding line {}\n", i));
        }
        source.push_str("export let dataFetchSeq = 0;\n");

        let report = analyze_definition_order(&source, Language::JavaScript);
        assert_eq!(report.issues.len(), 1, "issues: {:?}", report.issues);
        let issue = &report.issues[0];
        assert_eq!(issue.symbol, "dataFetchSeq");
        assert_eq!(issue.kind, "let");
        assert_eq!(issue.use_line, 2);
        assert_eq!(issue.definition_line, 174);
    }

    // (b) Function declarations are hoisted — using one before its
    // declaration is TDZ-safe and must NOT be flagged.
    #[test]
    fn js_hoisted_function_use_is_not_flagged() {
        let source = "\
const result = compute();
function compute() {
  return 1;
}
console.log(result);
";
        let report = analyze_definition_order(source, Language::JavaScript);
        assert!(report.issues.is_empty(), "issues: {:?}", report.issues);
        assert_eq!(report.checked_definitions, 2);
    }

    // (b') `var` is hoisted too.
    #[test]
    fn js_hoisted_var_use_is_not_flagged() {
        let source = "\
function edit() {
  return counter;
}
var counter = 0;
";
        let report = analyze_definition_order(source, Language::JavaScript);
        assert!(report.issues.is_empty(), "issues: {:?}", report.issues);
    }

    // (c) const used before declaration at module level → flagged.
    #[test]
    fn js_module_level_const_use_before_decl_is_flagged() {
        let source = "\
console.log(config);
const config = {};
";
        let report = analyze_definition_order(source, Language::JavaScript);
        assert_eq!(report.issues.len(), 1, "issues: {:?}", report.issues);
        let issue = &report.issues[0];
        assert_eq!(issue.symbol, "config");
        assert_eq!(issue.kind, "const");
        assert_eq!(issue.use_line, 1);
        assert_eq!(issue.definition_line, 2);
        assert_eq!(issue.snippet, "console.log(config);");
    }

    // (c') class used before its declaration → flagged (TDZ kind).
    #[test]
    fn js_class_use_before_decl_is_flagged() {
        let source = "\
const factory = () => new Widget();
class Widget {}
";
        let report = analyze_definition_order(source, Language::JavaScript);
        assert_eq!(report.issues.len(), 1, "issues: {:?}", report.issues);
        assert_eq!(report.issues[0].symbol, "Widget");
        assert_eq!(report.issues[0].kind, "class");
    }

    // Conservative false-positive guards: property accesses, shadowing
    // declarations and clean files must not produce issues.
    #[test]
    fn js_property_access_and_shadowing_are_not_flagged() {
        // `obj.dataFetchSeq` is a property access, and the function's own
        // parameter shadows the module-level `let`.
        let source = "\
const obj = {};
function edit(dataFetchSeq) {
  return obj.dataFetchSeq + dataFetchSeq;
}
let dataFetchSeq = 0;
";
        let report = analyze_definition_order(source, Language::JavaScript);
        assert!(report.issues.is_empty(), "issues: {:?}", report.issues);
    }

    #[test]
    fn js_clean_file_has_zero_issues() {
        let source = "\
const config = { name: 'app' };

function render() {
  return config.name;
}

render();
";
        let report = analyze_definition_order(source, Language::JavaScript);
        assert!(report.issues.is_empty(), "issues: {:?}", report.issues);
        assert_eq!(report.checked_definitions, 2);
    }

    #[test]
    fn js_typescript_type_annotations_are_not_flagged() {
        // Type references are `type_identifier` in the TS grammar and TS
        // types are hoisted — a `let` used as a value before decl is still
        // flagged, but type positions never are.
        let source = "\
function edit() {
  return dataFetchSeq;
}
let dataFetchSeq: number = 0;
";
        let report = analyze_definition_order(source, Language::TypeScript);
        assert_eq!(report.language, "typescript");
        assert_eq!(report.issues.len(), 1, "issues: {:?}", report.issues);
        assert_eq!(report.issues[0].symbol, "dataFetchSeq");
    }

    // (d) Python: module-level read before its module-level assignment.
    #[test]
    fn python_module_level_read_before_assignment_is_flagged() {
        let source = "\
print(config)
config = {}
";
        let report = analyze_definition_order(source, Language::Python);
        assert_eq!(report.language, "python");
        assert_eq!(report.issues.len(), 1, "issues: {:?}", report.issues);
        let issue = &report.issues[0];
        assert_eq!(issue.symbol, "config");
        assert_eq!(issue.kind, "assignment");
        assert_eq!(issue.use_line, 1);
        assert_eq!(issue.definition_line, 2);
        assert_eq!(issue.snippet, "print(config)");
    }

    // (d) Python: def called at the bottom after all defs → clean. Also
    // reads inside functions are never considered.
    #[test]
    fn python_def_called_after_defs_is_clean() {
        let source = "\
def main():
    helper = 1
    return helper


def helper_unused():
    return undefined_later


if __name__ == '__main__':
    main()
";
        let report = analyze_definition_order(source, Language::Python);
        assert!(report.issues.is_empty(), "issues: {:?}", report.issues);
        assert_eq!(report.checked_definitions, 2);
    }

    #[test]
    fn python_read_inside_function_is_not_flagged() {
        // The function body reads `config` but the function is only CALLED
        // after the binding — conservative scope keeps this clean.
        let source = "\
def render():
    return config.name

config = {}
";
        let report = analyze_definition_order(source, Language::Python);
        assert!(report.issues.is_empty(), "issues: {:?}", report.issues);
    }

    #[test]
    fn python_module_level_def_read_before_def_is_flagged() {
        let source = "\
main()

def main():
    return 1
";
        let report = analyze_definition_order(source, Language::Python);
        assert_eq!(report.issues.len(), 1, "issues: {:?}", report.issues);
        assert_eq!(report.issues[0].symbol, "main");
        assert_eq!(report.issues[0].kind, "function");
        assert_eq!(report.issues[0].use_line, 1);
        assert_eq!(report.issues[0].definition_line, 3);
    }

    #[test]
    fn python_attribute_and_writes_are_not_reads() {
        let source = "\
obj.attr = other.value
config = {}
print(obj.attr, config.name)
";
        let report = analyze_definition_order(source, Language::Python);
        // `other` and `obj` have no module bindings; `config` is bound at
        // line 2 and read at line 3 (after) — nothing to flag.
        assert!(report.issues.is_empty(), "issues: {:?}", report.issues);
        assert_eq!(report.checked_definitions, 1);
    }

    // (e) Unsupported language → explanation set, zero issues.
    #[test]
    fn unsupported_language_returns_explanation_and_zero_issues() {
        let report = analyze_definition_order("func main() {}", Language::Go);
        assert!(report.issues.is_empty());
        assert_eq!(report.checked_definitions, 0);
        assert_eq!(
            report.explanation.as_deref(),
            Some("definition-order analysis not yet supported for go")
        );
        assert_eq!(report.language, "go");
    }

    #[test]
    fn unsupported_language_rust_and_ruby_also_explain() {
        for (lang, name) in [(Language::Rust, "rust"), (Language::Ruby, "ruby")] {
            let report = analyze_definition_order("", lang);
            assert!(report.issues.is_empty());
            assert!(report
                .explanation
                .as_deref()
                .unwrap_or("")
                .contains(&format!("not yet supported for {}", name)));
        }
    }

    // Serialization shape: additive-field conventions hold.
    #[test]
    fn report_serializes_with_expected_fields() {
        let source = "console.log(config);\nconst config = {};\n";
        let mut report = analyze_definition_order(source, Language::JavaScript);
        report.file = "src/app.js".to_string();
        let json = serde_json::to_value(&report).expect("serialize");
        assert_eq!(json["file"], "src/app.js");
        assert_eq!(json["language"], "javascript");
        assert_eq!(json["checked_definitions"], 1);
        assert_eq!(json["issues"][0]["symbol"], "config");
        assert_eq!(json["issues"][0]["kind"], "const");
        assert_eq!(json["issues"][0]["use_line"], 1);
        assert_eq!(json["issues"][0]["definition_line"], 2);
        // explanation is skip_serializing_if None — absent on clean analyses.
        assert!(json.get("explanation").is_none());
    }

    #[test]
    fn report_deserializes_back() {
        let source = "console.log(config);\nconst config = {};\n";
        let report = analyze_definition_order(source, Language::JavaScript);
        let json = serde_json::to_string(&report).expect("serialize");
        let round: OrderReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(round.issues, report.issues);
        assert_eq!(round.checked_definitions, report.checked_definitions);
    }
}
