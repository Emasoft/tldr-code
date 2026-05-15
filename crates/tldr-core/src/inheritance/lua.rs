//! Lua inheritance walker.
//!
//! inheritance-walker-per-lang-v1 (M-039): detect the
//! `setmetatable(child, { __index = parent })` OOP idiom that Lua
//! programs use for prototype-style inheritance.
//!
//! Recognized constructs:
//!
//! | Construct                                              | Edge / kind        |
//! |--------------------------------------------------------|--------------------|
//! | `setmetatable(Child, { __index = Parent })`            | Child -> Parent    |
//! | `setmetatable(Child, Parent)` (when Parent is a table) | Child -> Parent    |
//!
//! Both forms produce an `extends` edge from the child table identifier
//! to the parent identifier.

use std::path::Path;

use tree_sitter::Node;

use crate::ast::parser::ParserPool;
use crate::types::{InheritanceKind, InheritanceNode, Language};
use crate::TldrResult;

/// Extract Lua tables that use `setmetatable` for prototype-style
/// inheritance.
pub fn extract_classes(
    source: &str,
    file_path: &Path,
    parser_pool: &ParserPool,
) -> TldrResult<Vec<InheritanceNode>> {
    let tree = parser_pool.parse(source, Language::Lua)?;
    let mut classes: Vec<InheritanceNode> = Vec::new();
    let mut seen_children: std::collections::HashSet<String> =
        std::collections::HashSet::new();

    let root = tree.root_node();
    visit_node(
        &root,
        source,
        file_path,
        &mut classes,
        &mut seen_children,
    );

    Ok(classes)
}

fn visit_node(
    node: &Node,
    source: &str,
    file_path: &Path,
    classes: &mut Vec<InheritanceNode>,
    seen_children: &mut std::collections::HashSet<String>,
) {
    // Tree-sitter-lua surfaces `setmetatable(a, b)` as a
    // `function_call` whose first child is an `identifier`/`variable`
    // (the callee) and second child holds the argument list.
    if let Some((child, parent, line)) = match_setmetatable_inheritance(node, source) {
        // Skip self-references / pure metatable-on-self cases such as
        // `setmetatable({}, ClassName)` inside a constructor — those
        // are instance creation, not class-level inheritance. We do
        // emit the edge only when child is a named, top-level table
        // identifier that we haven't already emitted as a child node.
        if !child.is_empty() && !parent.is_empty() && child != parent {
            if seen_children.insert(child.clone()) {
                let mut inode = InheritanceNode::new(
                    child,
                    file_path.to_path_buf(),
                    line,
                    Language::Lua,
                );
                inode.bases.push(parent);
                inode.base_kinds = Some(vec![InheritanceKind::Extends]);
                classes.push(inode);
            } else {
                // Already have a node for this child — add the new
                // base to its bases vector if not already present.
                if let Some(existing) = classes.iter_mut().find(|c| c.name == child) {
                    if !existing.bases.iter().any(|b| b == &parent) {
                        existing.bases.push(parent);
                        let kinds =
                            existing.base_kinds.get_or_insert_with(Vec::new);
                        kinds.push(InheritanceKind::Extends);
                    }
                }
            }
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        visit_node(&child, source, file_path, classes, seen_children);
    }
}

/// Match a `setmetatable(Child, { __index = Parent })` or
/// `setmetatable(Child, Parent)` call and return `(child, parent,
/// line)`.
///
/// Returns `None` if the node isn't a setmetatable call or the
/// arguments don't conform to one of the two recognized shapes.
fn match_setmetatable_inheritance(
    node: &Node,
    source: &str,
) -> Option<(String, String, u32)> {
    if node.kind() != "function_call" {
        return None;
    }

    // The callee identifier is the first non-trivia child.
    let callee = first_named_child(node)?;
    let callee_text = callee.utf8_text(source.as_bytes()).ok()?.trim();
    if callee_text != "setmetatable" {
        return None;
    }

    // Locate the argument list. tree-sitter-lua nests args in an
    // `arguments` node containing the two expressions.
    let args = find_child_of_kind(node, "arguments")?;
    let arg_exprs = collect_argument_expressions(&args, source);
    if arg_exprs.len() < 2 {
        return None;
    }

    let child_name = identifier_text(&arg_exprs[0], source)?;
    let parent_name = extract_parent_from_metatable(&arg_exprs[1], source)?;
    let line = node.start_position().row as u32 + 1;
    Some((child_name, parent_name, line))
}

/// Get the first named (non-whitespace/non-punctuation) child.
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

/// Pull the parent identifier out of the second `setmetatable`
/// argument.
///
/// Recognizes:
///   - a bare identifier: `setmetatable(Child, Parent)`
///   - a table constructor `{ __index = Parent }`:
///     `setmetatable(Child, { __index = Parent })`
fn extract_parent_from_metatable(node: &Node, source: &str) -> Option<String> {
    match node.kind() {
        // Some grammar versions name this `table_constructor`; older
        // ones use `table`. We accept both.
        "table_constructor" | "table" => find_index_field_value(node, source),
        _ => identifier_text(node, source),
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
}
