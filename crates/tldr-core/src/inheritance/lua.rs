//! Lua / Luau inheritance walker.
//!
//! inheritance-walker-per-lang-v1 (M-039) + v0.5.0 AUDIT-FIX
//! (W2-lua-inheritance): detect the prototype-style inheritance idioms
//! that real Lua / Luau programs use, modelled directly on the AST shapes
//! emitted by tree-sitter-lua 0.2.0 and tree-sitter-luau 1.2.0 (both
//! grammars share these node kinds).
//!
//! Recognized constructs (all emit a `Child -> Parent` `extends` edge):
//!
//! | Construct                                              | Notes                |
//! |--------------------------------------------------------|----------------------|
//! | `setmetatable(Child, { __index = Parent })`            | classic prototype    |
//! | `local Child = setmetatable({...}, { __index = Parent })` | assigned form     |
//! | `local Child = Parent:extend()`                        | luvit / middleclass  |
//! | `local Child = Parent:extend("Name")`                  | Roact-style (string  |
//! |                                                        | arg is the *name*,   |
//! |                                                        | not the parent)      |
//! | `local Child = require('mod').Parent:extend()`         | required-base form   |
//! | `Child = Parent:extend()` (top-level, no `local`)      | same, bare assign    |
//!
//! Crucially we do **not** emit an edge for the bare
//! `setmetatable(instance, metatable)` form (e.g. `setmetatable(self, M)`,
//! `setmetatable(obj, Emitter.meta)`). In real corpora that two-argument
//! identifier form is *instance construction*, not class inheritance, and
//! treating it as inheritance produced a flood of bogus edges
//! (`ustr -> _meta`, `editor -> Editor`, `instance -> self`, ...). Genuine
//! class inheritance is expressed either through an explicit `__index`
//! metatable or through a `:extend()` call, both of which we detect
//! structurally.

use std::path::Path;

use tree_sitter::Node;

use crate::ast::parser::ParserPool;
use crate::types::{InheritanceKind, InheritanceNode, Language};
use crate::TldrResult;

/// Extract Lua / Luau tables that participate in prototype-style
/// inheritance.
///
/// The grammar (`function_call`, `method_index_expression`,
/// `dot_index_expression`, `assignment_statement`, `table_constructor`)
/// is identical between tree-sitter-lua and tree-sitter-luau for every
/// node this walker inspects, so a single walker serves both languages.
/// We parse with the grammar matching the file extension so `.luau`
/// sources (typed params, `type` aliases) tokenize correctly.
pub fn extract_classes(
    source: &str,
    file_path: &Path,
    parser_pool: &ParserPool,
) -> TldrResult<Vec<InheritanceNode>> {
    let lang = language_for_path(file_path);
    let tree = parser_pool.parse(source, lang)?;
    let mut classes: Vec<InheritanceNode> = Vec::new();
    let mut seen_children: std::collections::HashSet<String> =
        std::collections::HashSet::new();

    let root = tree.root_node();
    visit_node(
        &root,
        source,
        file_path,
        lang,
        &mut classes,
        &mut seen_children,
    );

    Ok(classes)
}

/// Choose the tree-sitter grammar based on the file extension. `.luau`
/// files must be parsed with the Luau grammar (typed parameters / `type`
/// definitions); everything else defaults to the Lua grammar.
fn language_for_path(file_path: &Path) -> Language {
    match file_path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .as_deref()
    {
        Some("luau") => Language::Luau,
        _ => Language::Lua,
    }
}

fn visit_node(
    node: &Node,
    source: &str,
    file_path: &Path,
    lang: Language,
    classes: &mut Vec<InheritanceNode>,
    seen_children: &mut std::collections::HashSet<String>,
) {
    // 1. Standalone `setmetatable(Child, { __index = Parent })` calls.
    //    The bare `setmetatable(instance, metatable)` form is treated as
    //    instance construction (NOT inheritance) and rejected inside the
    //    matcher, so it never reaches here.
    if let Some((child, parent, line)) = match_setmetatable_inheritance(node, source) {
        emit_edge(child, parent, line, file_path, lang, classes, seen_children);
    }

    // 2. Assignment-driven idioms:
    //      `local Child = Parent:extend()`           (luvit / middleclass)
    //      `local Child = Parent:extend("Name")`     (Roact)
    //      `local Child = require('m').Parent:extend()`
    //      `Child = Parent:extend()`                 (top-level, no local)
    //      `local Child = setmetatable({...}, { __index = Parent })`
    //    The `local` form wraps the `assignment_statement` inside a
    //    `variable_declaration`; handling `assignment_statement` here
    //    covers both because the bare node is visited directly and the
    //    wrapped one is reached by recursion below.
    if node.kind() == "assignment_statement" {
        for (child, parent, line) in match_assignment_inheritance(node, source) {
            emit_edge(child, parent, line, file_path, lang, classes, seen_children);
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        visit_node(&child, source, file_path, lang, classes, seen_children);
    }
}

/// Record a single `child -> parent` extends edge, de-duplicating both
/// the child node and repeated bases. Skips empty / self / anonymous
/// names so instance temporaries never leak into the graph.
fn emit_edge(
    child: String,
    parent: String,
    line: u32,
    file_path: &Path,
    lang: Language,
    classes: &mut Vec<InheritanceNode>,
    seen_children: &mut std::collections::HashSet<String>,
) {
    if child.is_empty()
        || parent.is_empty()
        || child == parent
        || !is_valid_child_name(&child)
        || !is_valid_parent_name(&parent)
    {
        return;
    }

    if seen_children.insert(child.clone()) {
        let mut inode = InheritanceNode::new(child, file_path.to_path_buf(), line, lang);
        inode.bases.push(parent);
        inode.base_kinds = Some(vec![InheritanceKind::Extends]);
        classes.push(inode);
    } else if let Some(existing) = classes.iter_mut().find(|c| c.name == child) {
        // Already have a node for this child — add the new base if not
        // already present.
        if !existing.bases.iter().any(|b| b == &parent) {
            existing.bases.push(parent);
            let kinds = existing.base_kinds.get_or_insert_with(Vec::new);
            kinds.push(InheritanceKind::Extends);
        }
    }
}

/// A child of an inheritance edge must be a real, named class table.
/// `self`, `_`, and anonymous receivers are instance/temporary names and
/// must never be emitted as classes.
fn is_valid_child_name(name: &str) -> bool {
    !matches!(name, "self" | "_") && !name.is_empty()
}

/// The parent may be a dotted/required reference (e.g.
/// `require('core').Object`), but `self` / `_` are never valid bases.
fn is_valid_parent_name(name: &str) -> bool {
    !matches!(name, "self" | "_") && !name.is_empty()
}

/// Match a *standalone* `setmetatable(Child, { __index = Parent })` call
/// (i.e. one whose result is not bound to a name) and return
/// `(child, parent, line)`.
///
/// Only the `{ __index = Parent }` table-constructor metatable form is
/// accepted. The bare `setmetatable(Child, Parent)` two-identifier form is
/// deliberately rejected: in real Lua/Luau code that shape is instance
/// construction (`setmetatable(obj, Class)`, `setmetatable(self, M)`,
/// `setmetatable(history, History)`), not class-level inheritance, and
/// matching it produced ~20 bogus edges in the audit corpus. Genuine
/// "extends with a metatable" still works through the `__index` form here
/// and through the assigned form in [`match_assignment_inheritance`].
///
/// Returns `None` when the node isn't such a call.
fn match_setmetatable_inheritance(
    node: &Node,
    source: &str,
) -> Option<(String, String, u32)> {
    let (arg_exprs, line) = setmetatable_args(node, source)?;
    if arg_exprs.len() < 2 {
        return None;
    }

    // arg0 must be a concrete named receiver. When it is an anonymous
    // table constructor (`setmetatable({}, ...)`) the child name lives on
    // the assignment LHS and is recovered by the assignment handler, so we
    // skip it here to avoid emitting an anonymous child.
    let child_name = identifier_text(&arg_exprs[0], source)?;

    // arg1 must be a `{ __index = Parent }` table constructor. A bare
    // identifier metatable is instance construction, not inheritance.
    let parent_name = parent_from_index_metatable(&arg_exprs[1], source)?;
    Some((child_name, parent_name, line))
}

/// Shared helper: if `node` is a `setmetatable(...)` call, return its
/// top-level argument expressions and 1-based line.
fn setmetatable_args<'a>(
    node: &Node<'a>,
    source: &str,
) -> Option<(Vec<Node<'a>>, u32)> {
    if node.kind() != "function_call" {
        return None;
    }
    let callee = first_named_child(node)?;
    let callee_text = callee.utf8_text(source.as_bytes()).ok()?.trim();
    if callee_text != "setmetatable" {
        return None;
    }
    let args = find_child_of_kind(node, "arguments")?;
    let arg_exprs = collect_argument_expressions(&args, source);
    let line = node.start_position().row as u32 + 1;
    Some((arg_exprs, line))
}

/// Extract `Parent` from a `{ __index = Parent }` table constructor.
/// Returns `None` for any other metatable shape (bare identifier,
/// `{ __index = function ... }`, plain config tables, ...), which is how
/// we keep instance-construction `setmetatable` calls out of the graph.
fn parent_from_index_metatable(node: &Node, source: &str) -> Option<String> {
    match node.kind() {
        "table_constructor" | "table" => find_index_field_value(node, source),
        _ => None,
    }
}

/// Detect inheritance expressed through an assignment's right-hand side.
///
/// Handles (pairing each LHS name in `variable_list` with the matching
/// RHS expression in `expression_list`):
///   * `Child = Parent:extend(...)`  -> `method_index_expression`
///     callee whose `method` is `extend`; the `table` field is the
///     parent (its dotted tail is used, e.g. `require('m').Parent` ->
///     `Parent`). Any string argument is the *class name*, not a base, so
///     it is ignored.
///   * `Child = setmetatable({...}, { __index = Parent })` -> the
///     anonymous-receiver metatable form, with the child taken from the
///     LHS.
fn match_assignment_inheritance(
    node: &Node,
    source: &str,
) -> Vec<(String, String, u32)> {
    let mut out = Vec::new();
    let var_list = match find_child_of_kind(node, "variable_list") {
        Some(v) => v,
        None => return out,
    };
    let expr_list = match find_child_of_kind(node, "expression_list") {
        Some(e) => e,
        None => return out,
    };

    let names: Vec<Node> = named_children(&var_list);
    let values: Vec<Node> = named_children(&expr_list);

    for (i, value) in values.iter().enumerate() {
        let name_node = match names.get(i) {
            Some(n) => n,
            None => break,
        };
        let child = match identifier_text(name_node, source) {
            Some(c) => c,
            None => continue,
        };
        let line = value.start_position().row as u32 + 1;

        if let Some(parent) = parent_from_extend_call(value, source) {
            out.push((child, parent, line));
        } else if let Some(parent) = parent_from_assigned_setmetatable(value, source) {
            out.push((child, parent, line));
        }
    }
    out
}

/// If `value` is a `Parent:extend(...)` call, return the parent name.
///
/// AST shape: `function_call { name: method_index_expression { table:
/// <parent>, method: `extend` } }`. The parent is reconstructed from the
/// `table` field; for a dotted/required base (`require('m').Parent`) the
/// trailing identifier is used as the class name.
fn parent_from_extend_call(value: &Node, source: &str) -> Option<String> {
    if value.kind() != "function_call" {
        return None;
    }
    let name = value.child_by_field_name("name")?;
    if name.kind() != "method_index_expression" {
        return None;
    }
    let method = name.child_by_field_name("method")?;
    let method_text = method.utf8_text(source.as_bytes()).ok()?.trim();
    if method_text != "extend" {
        return None;
    }
    let table = name.child_by_field_name("table")?;
    let full = identifier_text(&table, source)?;
    // Use the trailing component for dotted/required bases so
    // `require('core').Object` -> `Object`, while a plain `Parent`
    // stays `Parent`.
    Some(dotted_tail(&full))
}

/// If `value` is `setmetatable({...}, { __index = Parent })` (the
/// assigned, anonymous-receiver form), return the parent name. The child
/// comes from the assignment LHS in the caller.
fn parent_from_assigned_setmetatable(value: &Node, source: &str) -> Option<String> {
    let (arg_exprs, _line) = setmetatable_args(value, source)?;
    if arg_exprs.len() < 2 {
        return None;
    }
    parent_from_index_metatable(&arg_exprs[1], source)
}

/// Return the trailing identifier of a dotted reference: `a.b.c` -> `c`,
/// `Parent` -> `Parent`. Colon method receivers never reach here.
fn dotted_tail(name: &str) -> String {
    name.rsplit('.').next().unwrap_or(name).trim().to_string()
}

/// Collect the named (non-trivia) children of a node.
fn named_children<'a>(node: &Node<'a>) -> Vec<Node<'a>> {
    let mut out = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.is_named() {
            out.push(child);
        }
    }
    out
}

/// Get the first named (non-whitespace/non-punctuation) child.
//
// NB: the explicit loop is required rather than `Iterator::find` because
// the returned `Node` must outlive the local `cursor`; the `find` form
// fails the borrow checker.
fn first_named_child<'a>(node: &Node<'a>) -> Option<Node<'a>> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.is_named() {
            return Some(child);
        }
    }
    None
}

/// Find the first direct child of the given `kind`.
//
// See `first_named_child` for why this is a loop and not `Iterator::find`.
fn find_child_of_kind<'a>(node: &Node<'a>, kind: &str) -> Option<Node<'a>> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == kind {
            return Some(child);
        }
    }
    None
}

/// Collect the top-level expression children of an `arguments` node,
/// skipping commas and parentheses.
fn collect_argument_expressions<'a>(args: &Node<'a>, _source: &str) -> Vec<Node<'a>> {
    let mut out: Vec<Node<'a>> = Vec::new();
    let mut cursor = args.walk();
    for child in args.children(&mut cursor) {
        if child.is_named() {
            out.push(child);
        }
    }
    out
}

/// Get the text of a node when it is an identifier-like expression.
fn identifier_text(node: &Node, source: &str) -> Option<String> {
    match node.kind() {
        "identifier" | "variable" | "dot_index_expression" | "method_index_expression" => node
            .utf8_text(source.as_bytes())
            .ok()
            .map(|s| s.trim().to_string()),
        _ => {
            // Some grammar versions wrap identifiers inside `prefix`
            // or `expression` nodes — descend to the first named
            // child.
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.is_named() {
                    return identifier_text(&child, source);
                }
            }
            // Fall back to raw text — only meaningful when the source
            // text is itself a bare identifier.
            let txt = node.utf8_text(source.as_bytes()).ok()?.trim();
            if txt
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
                && !txt.is_empty()
            {
                Some(txt.to_string())
            } else {
                None
            }
        }
    }
}

/// Inside a table constructor, find the value of the `__index` field.
///
/// The grammar represents `{ __index = Parent }` as a sequence of
/// `field` nodes; each `field` has a `name` child (identifier or
/// `[...]` key) and a `value` (the rhs).
fn find_index_field_value(table: &Node, source: &str) -> Option<String> {
    let mut cursor = table.walk();
    for field in table.children(&mut cursor) {
        if field.kind() != "field" {
            continue;
        }
        // Two shapes:
        //   `name = value` -> field has `name` (identifier) + `value`
        //                     fields.
        //   `[key] = value` -> bracket key, ignored here.
        let key_node = field
            .child_by_field_name("name")
            .or_else(|| field_first_identifier(&field));
        let key_text = key_node.and_then(|n| n.utf8_text(source.as_bytes()).ok());
        if key_text.map(|t| t.trim() == "__index").unwrap_or(false) {
            let value = field
                .child_by_field_name("value")
                .or_else(|| field_last_expression(&field, source));
            if let Some(v) = value {
                return identifier_text(&v, source);
            }
        }
    }
    None
}

/// Get the first identifier child of a `field` node.
//
// See `first_named_child` for why this is a loop and not `Iterator::find`.
fn field_first_identifier<'a>(field: &Node<'a>) -> Option<Node<'a>> {
    let mut cursor = field.walk();
    for child in field.children(&mut cursor) {
        if child.kind() == "identifier" {
            return Some(child);
        }
    }
    None
}

/// Get the last expression-like child of a `field` (used when the
/// grammar version doesn't expose a `value` field name).
fn field_last_expression<'a>(field: &Node<'a>, _source: &str) -> Option<Node<'a>> {
    let mut last: Option<Node<'a>> = None;
    let mut cursor = field.walk();
    for child in field.children(&mut cursor) {
        if child.is_named() {
            last = Some(child);
        }
    }
    last
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn parse_and_extract(source: &str) -> Vec<InheritanceNode> {
        let pool = ParserPool::new();
        extract_classes(source, &PathBuf::from("test.lua"), &pool).unwrap()
    }

    fn extends_base(classes: &[InheritanceNode], child: &str, parent: &str) -> bool {
        classes
            .iter()
            .find(|c| c.name == child)
            .map(|c| c.bases.iter().any(|b| b == parent))
            .unwrap_or(false)
    }

    #[test]
    fn test_setmetatable_index_inheritance() {
        let source = r#"
Animal = {}
Dog = {}
setmetatable(Dog, { __index = Animal })
"#;
        let classes = parse_and_extract(source);
        let dog = classes.iter().find(|c| c.name == "Dog").unwrap();
        assert!(dog.bases.contains(&"Animal".to_string()));
        assert_eq!(
            dog.base_kinds.as_ref().unwrap()[0],
            InheritanceKind::Extends
        );
    }

    // v0.5.0 AUDIT-FIX (W2-lua-inheritance) ---------------------------------

    /// `local Child = Parent:extend()` is the dominant luvit / Roblox OOP
    /// idiom and MUST produce a `Child -> Parent` edge. (RED before fix:
    /// the walker only looked at `setmetatable`, so `:extend()` yielded
    /// nothing.)
    #[test]
    fn test_extend_method_inheritance() {
        let source = r#"
local Animal = {}
local Dog = Animal:extend()
"#;
        let classes = parse_and_extract(source);
        assert!(
            extends_base(&classes, "Dog", "Animal"),
            "expected Dog -> Animal via :extend(), got {:?}",
            classes
        );
        let dog = classes.iter().find(|c| c.name == "Dog").unwrap();
        assert_eq!(dog.base_kinds.as_ref().unwrap()[0], InheritanceKind::Extends);
    }

    /// Top-level (non-`local`) `Child = Parent:extend()` and a chained
    /// require base `require('core').Object:extend()` both resolve, the
    /// latter to the dotted tail `Object`.
    #[test]
    fn test_extend_toplevel_and_required_base() {
        let source = r#"
local Foo = require('core').Object:extend()
Bar = Foo:extend()
"#;
        let classes = parse_and_extract(source);
        assert!(
            extends_base(&classes, "Foo", "Object"),
            "expected Foo -> Object (dotted tail of require('core').Object), got {:?}",
            classes
        );
        assert!(
            extends_base(&classes, "Bar", "Foo"),
            "expected Bar -> Foo from top-level assignment, got {:?}",
            classes
        );
    }

    /// Roact-style `Component:extend("Name")`: the string argument is the
    /// component *name*, not a base. The edge is still `Child -> Component`
    /// and the string must never become a parent.
    #[test]
    fn test_extend_with_string_name_arg() {
        let source = r#"
local Component = {}
local PureComponent = Component:extend("PureComponent")
"#;
        let classes = parse_and_extract(source);
        assert!(
            extends_base(&classes, "PureComponent", "Component"),
            "expected PureComponent -> Component, got {:?}",
            classes
        );
        let pc = classes
            .iter()
            .find(|c| c.name == "PureComponent")
            .unwrap();
        assert_eq!(pc.bases, vec!["Component".to_string()]);
        assert!(
            !pc.bases.iter().any(|b| b.contains("PureComponent")),
            "string name arg must not be treated as a base: {:?}",
            pc.bases
        );
    }

    /// Assigned metatable form `local Child = setmetatable({}, { __index =
    /// Parent })` recovers the child name from the LHS.
    #[test]
    fn test_assigned_setmetatable_index() {
        let source = r#"
local Animal = {}
local Dog = setmetatable({}, { __index = Animal })
"#;
        let classes = parse_and_extract(source);
        assert!(
            extends_base(&classes, "Dog", "Animal"),
            "expected Dog -> Animal via assigned setmetatable, got {:?}",
            classes
        );
    }

    /// NEGATIVE: bare `setmetatable(instance, metatable)` is instance
    /// construction, not inheritance, and MUST NOT emit any edge. (RED
    /// before fix: these produced bogus edges such as `e -> Emitter.meta`
    /// and `editor -> Editor`.)
    #[test]
    fn test_bare_setmetatable_instance_is_not_inheritance() {
        let source = r#"
local Emitter = {}
function Emitter.new()
  local e = {}
  setmetatable(e, Emitter.meta)
  return e
end

local function make(history)
  return setmetatable(history, History)
end

local obj = setmetatable(self, M)
"#;
        let classes = parse_and_extract(source);
        assert!(
            !classes.iter().any(|c| c.name == "e"),
            "instance temp `e` must not be a class: {:?}",
            classes
        );
        assert!(
            !classes.iter().any(|c| c.name == "history"),
            "instance temp `history` must not be a class: {:?}",
            classes
        );
        assert!(
            !classes.iter().any(|c| c.name == "self" || c.name == "obj"),
            "`self`/anonymous receiver must not be a class: {:?}",
            classes
        );
        // No bogus edges at all from this instance-only file.
        assert!(
            classes.is_empty(),
            "expected no inheritance edges from instance-construction file, got {:?}",
            classes
        );
    }

    /// `.luau` files parse with the Luau grammar and the same `:extend()`
    /// idiom resolves (typed return annotations don't break detection).
    #[test]
    fn test_luau_extend_inheritance() {
        let pool = ParserPool::new();
        let source = r#"
local Component = {}
local Button = Component:extend("Button")
function Button.render(self): number
    return 1
end
"#;
        let classes =
            extract_classes(source, &PathBuf::from("Button.luau"), &pool).unwrap();
        assert!(
            extends_base(&classes, "Button", "Component"),
            "expected Button -> Component in .luau, got {:?}",
            classes
        );
    }
}
