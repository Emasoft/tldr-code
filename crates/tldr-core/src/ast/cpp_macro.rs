//! Shared cpp macro-decorated class recovery
//! (`m040-cpp-macro-class-cross-pipeline-v1`, v0.4.2 M-110).
//!
//! tree-sitter-cpp misparses
//!
//! ```cpp
//! class TINYXML2_LIB XMLDocument : public XMLNode { ... };
//! ```
//!
//! as a `function_definition` whose children are:
//!
//! | child         | role                                              |
//! |---------------|---------------------------------------------------|
//! | `class_specifier` | carries `class MACRO` and is itself a parser-emitted forward-decl shape (no `field_declaration_list` child). |
//! | `identifier`  | the **real** class name (the one this helper returns).      |
//! | `ERROR`       | (optional) carries the rest of the class header (e.g. `: public XMLNode`). |
//! | `compound_statement` | the class body.                              |
//!
//! Wave-13 M-040 added this recovery inline to the call-graph cpp handler
//! at `crates/tldr-core/src/callgraph/languages/cpp.rs`. Wave-17c (this
//! module) extracts the helper to a shared location so the four sibling
//! pipelines (`structure`, `extract`, `definition`, `cohesion`) all use
//! the same single source of truth — closing the cross-pipeline drift
//! flagged in `iter-2/cpp.md` Probe L-1.
//!
//! AST-only: we never inspect the macro identifier text or apply regex.
//! The recovery decision is made purely from the children shape of the
//! `function_definition` node.

use tree_sitter::Node;

/// Returns the recovered class name when `node` is the misparse shape
/// described above, and `None` otherwise. `node` is expected to be a
/// `function_definition` node from a tree-sitter-cpp parse tree.
///
/// Returning `None` lets callers fall through to their normal
/// function-name resolution path.
pub fn macro_decorated_class_name(node: &Node, source: &[u8]) -> Option<String> {
    let (name, _body) = macro_decorated_class_name_and_body(node, source)?;
    Some(name)
}

/// Returns `(class_name, body_node)` when `node` is the misparse shape,
/// otherwise `None`. The body node is the `compound_statement` carrying
/// the class members; callers that need to enumerate methods/fields
/// (e.g. `extract_cpp_classes_detailed`, `extract_cpp_methods_cohesion`)
/// can iterate it directly without re-walking the children.
pub fn macro_decorated_class_name_and_body<'tree>(
    node: &Node<'tree>,
    source: &[u8],
) -> Option<(String, Node<'tree>)> {
    let mut saw_class_specifier_without_body = false;
    let mut class_name: Option<String> = None;
    let mut body: Option<Node<'tree>> = None;

    for i in 0..node.child_count() {
        let Some(child) = node.child(i) else { continue };
        match child.kind() {
            "class_specifier" | "struct_specifier" => {
                // Must be the parser's forward-decl shape (no body).
                let has_body = (0..child.child_count())
                    .filter_map(|j| child.child(j))
                    .any(|c| c.kind() == "field_declaration_list");
                if has_body {
                    return None;
                }
                saw_class_specifier_without_body = true;
            }
            "identifier" if saw_class_specifier_without_body && class_name.is_none() => {
                let text = child
                    .utf8_text(source)
                    .ok()
                    .map(|s| s.to_string())
                    .unwrap_or_default();
                if !text.is_empty() {
                    class_name = Some(text);
                }
            }
            "compound_statement" => {
                body = Some(child);
            }
            _ => {}
        }
    }

    match (saw_class_specifier_without_body, class_name, body) {
        (true, Some(name), Some(b)) => Some((name, b)),
        _ => None,
    }
}

/// Returns `true` when `node` is the macro-misparse shape. Convenience
/// wrapper for call sites that only need to decide whether to skip the
/// node from a `function_definition` walk (e.g. the cpp `functions`
/// projection in `extract::extract_cpp_functions_detailed`).
pub fn is_macro_decorated_class(node: &Node, source: &[u8]) -> bool {
    macro_decorated_class_name(node, source).is_some()
}

/// Source-less structural detection: returns `true` when `node` is a
/// `function_definition` whose children match the macro-misparse shape
/// (bodyless `class_specifier`/`struct_specifier` followed by an
/// `identifier` and a `compound_statement`). This variant is used by
/// call sites that don't have the source-byte slice handy (e.g.
/// `is_inside_class_or_impl` in `ast/extractor.rs`, which only inspects
/// parent kinds when walking up an ancestor chain). The structural
/// check is identical to `macro_decorated_class_name` minus the
/// identifier-text extraction.
pub fn is_macro_decorated_class_node(node: &Node) -> bool {
    if node.kind() != "function_definition" {
        return false;
    }
    let mut saw_class_specifier_without_body = false;
    let mut saw_identifier_after = false;
    let mut saw_compound_statement = false;
    for i in 0..node.child_count() {
        let Some(child) = node.child(i) else { continue };
        match child.kind() {
            "class_specifier" | "struct_specifier" => {
                let has_body = (0..child.child_count())
                    .filter_map(|j| child.child(j))
                    .any(|c| c.kind() == "field_declaration_list");
                if has_body {
                    return false;
                }
                saw_class_specifier_without_body = true;
            }
            "identifier" if saw_class_specifier_without_body && !saw_identifier_after => {
                saw_identifier_after = true;
            }
            "compound_statement" => {
                saw_compound_statement = true;
            }
            _ => {}
        }
    }
    saw_class_specifier_without_body && saw_identifier_after && saw_compound_statement
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(src: &str) -> tree_sitter::Tree {
        let mut p = tree_sitter::Parser::new();
        p.set_language(&tree_sitter_cpp::LANGUAGE.into()).unwrap();
        p.parse(src, None).unwrap()
    }

    fn find_function_def<'a>(node: tree_sitter::Node<'a>) -> Option<tree_sitter::Node<'a>> {
        if node.kind() == "function_definition" {
            return Some(node);
        }
        for i in 0..node.child_count() {
            if let Some(c) = node.child(i) {
                if let Some(found) = find_function_def(c) {
                    return Some(found);
                }
            }
        }
        None
    }

    #[test]
    fn recovers_macro_decorated_class_name() {
        let src = "class TINYXML2_LIB XMLDocument : public XMLNode { void DeepCopy() {} };";
        let tree = parse(src);
        let func = find_function_def(tree.root_node()).expect("misparse should produce function_definition");
        let name = macro_decorated_class_name(&func, src.as_bytes());
        assert_eq!(name.as_deref(), Some("XMLDocument"));
    }

    #[test]
    fn returns_none_for_real_function_definition() {
        let src = "void deep_copy(int x) { return; }";
        let tree = parse(src);
        let func = find_function_def(tree.root_node()).expect("real function_definition");
        assert!(macro_decorated_class_name(&func, src.as_bytes()).is_none());
    }

    #[test]
    fn returns_body_node_for_misparse() {
        let src = "class API_EXPORT Foo : public Bar { void m() {} };";
        let tree = parse(src);
        let func = find_function_def(tree.root_node()).unwrap();
        let (name, body) = macro_decorated_class_name_and_body(&func, src.as_bytes())
            .expect("misparse expected");
        assert_eq!(name, "Foo");
        assert_eq!(body.kind(), "compound_statement");
    }
}
