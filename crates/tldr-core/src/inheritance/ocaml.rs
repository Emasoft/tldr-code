//! OCaml class-hierarchy extraction for inheritance analysis.
//!
//! inheritance-extends-vs-implements-ocaml-v1 (T3): the `inheritance` command
//! had no OCaml arm, so an OCaml repo's class hierarchy was either empty or —
//! worse, for a polyglot tree like `ocaml-lwt` — computed entirely from
//! vendored C stub files (`src/unix/unix_c/*.c`). This module gives OCaml a
//! real walker; the `mod.rs` language-selection fix stops the C files from
//! standing in for the project.
//!
//! # Grammar (tree-sitter-ocaml 0.24.2, VERIFIED against
//! `grammars/ocaml/src/node-types.json`)
//!
//! ```text
//! class_definition       > class_binding+
//! class_binding          { class_name, body: _class_expression, class_type?: _class_type }
//! class_type_definition  > class_type_binding+
//! class_type_binding     { class_type_name, body: _simple_class_type }
//!
//! object_expression      > _class_field*   (the `object … end` body)
//!   _class_field includes: inheritance_definition, method_definition,
//!                          instance_variable_definition, class_initializer
//! inheritance_definition { class: _class_expression, alias? }   // `inherit C`
//!
//! class_body_type        > object_type
//! object_type            > (_simple_type | method_type)*  +  inheritance_specification
//! inheritance_specification { class_type: _simple_class_type }  // `inherit ct`
//! ```
//!
//! The parent's NAME lives in a `class_path` (`class_name`) or `class_type_path`
//! (`class_type_name`), reachable by descending through the
//! `class_application` / `instantiated_class` / `typed_class_expression`
//! wrappers (e.g. `inherit common a b`, `inherit ['a] base`, `class d = base ()`).
//!
//! # Edge kind
//!
//! Every OCaml `inherit` (and the `class d = base` alias / `class d = base ()`
//! instantiation forms) is genuine class inheritance, so all edges are
//! [`InheritanceKind::Extends`].

use std::path::Path;

use tree_sitter::Node;

use crate::ast::parser::ParserPool;
use crate::types::{InheritanceKind, InheritanceNode, Language};
use crate::TldrResult;

/// Extract OCaml class and class-type definitions with their `inherit` edges.
pub fn extract_classes(
    source: &str,
    file_path: &Path,
    parser_pool: &ParserPool,
) -> TldrResult<Vec<InheritanceNode>> {
    let tree = parser_pool.parse(source, Language::Ocaml)?;
    let mut classes = Vec::new();
    visit_node(&tree.root_node(), source, file_path, &mut classes);
    Ok(classes)
}

fn visit_node(node: &Node, source: &str, file_path: &Path, classes: &mut Vec<InheritanceNode>) {
    match node.kind() {
        // `class a = … and b = …` — one node per binding.
        "class_definition" => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "class_binding" {
                    if let Some(c) = extract_class_binding(&child, source, file_path) {
                        classes.push(c);
                    }
                }
            }
        }
        // `class type t = object … end` — the OCaml interface analogue.
        "class_type_definition" => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "class_type_binding" {
                    if let Some(c) = extract_class_type_binding(&child, source, file_path) {
                        classes.push(c);
                    }
                }
            }
        }
        _ => {}
    }

    // Recurse so classes nested inside modules / structures are discovered.
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        visit_node(&child, source, file_path, classes);
    }
}

/// Build a node from a `class_binding` (`class [params] name = body`).
fn extract_class_binding(
    binding: &Node,
    source: &str,
    file_path: &Path,
) -> Option<InheritanceNode> {
    let name_node = child_of_kind(binding, "class_name")?;
    let name = node_text(&name_node, source)?;
    let line = binding.start_position().row as u32 + 1;

    let mut class_node = InheritanceNode::new(name, file_path.to_path_buf(), line, Language::Ocaml);

    let mut bases = Vec::new();
    if let Some(body) = binding.child_by_field_name("body") {
        collect_bases_from_class_expression(&body, source, &mut bases);
    }

    push_extends_bases(&mut class_node, bases);
    Some(class_node)
}

/// Build a node from a `class_type_binding` (`class type name = body`).
///
/// Marked `interface = Some(true)`: a `class type` is OCaml's class *signature*
/// (the structural-typing interface analogue).
fn extract_class_type_binding(
    binding: &Node,
    source: &str,
    file_path: &Path,
) -> Option<InheritanceNode> {
    let name_node = child_of_kind(binding, "class_type_name")?;
    let name = node_text(&name_node, source)?;
    let line = binding.start_position().row as u32 + 1;

    let mut class_node = InheritanceNode::new(name, file_path.to_path_buf(), line, Language::Ocaml);
    class_node.interface = Some(true);

    let mut bases = Vec::new();
    if let Some(body) = binding.child_by_field_name("body") {
        collect_bases_from_class_type(&body, source, &mut bases);
    }

    push_extends_bases(&mut class_node, bases);
    Some(class_node)
}

/// Attach `bases` to `node`, tagging every base `Extends` (OCaml `inherit` is
/// class inheritance). De-duplicates while preserving first-seen order.
fn push_extends_bases(node: &mut InheritanceNode, bases: Vec<String>) {
    let mut seen = std::collections::HashSet::new();
    let mut deduped = Vec::new();
    for b in bases {
        if seen.insert(b.clone()) {
            deduped.push(b);
        }
    }
    if !deduped.is_empty() {
        let kinds = vec![InheritanceKind::Extends; deduped.len()];
        node.bases = deduped;
        node.base_kinds = Some(kinds);
    }
}

/// Collect parent class names reachable from a `class_binding` body
/// (`_class_expression`).
///
/// Two shapes carry inheritance:
///   - `object_expression` — the normal `object … inherit P … end` body; the
///     parents are the `inheritance_definition` clauses inside it.
///   - a direct class reference (`class d = base` / `class d = base ()`) — the
///     RHS class itself IS the parent.
fn collect_bases_from_class_expression(node: &Node, source: &str, bases: &mut Vec<String>) {
    match node.kind() {
        "object_expression" => {
            let mut cursor = node.walk();
            for field in node.children(&mut cursor) {
                if field.kind() == "inheritance_definition" {
                    // `inherit <class_expression>` — descend the class expr.
                    if let Some(class_expr) = field.child_by_field_name("class") {
                        if let Some(name) = class_expression_name(&class_expr, source) {
                            bases.push(name);
                        }
                    }
                }
            }
        }
        // `class d = base` / `class d = base ()` / `class d = (base : ct)` —
        // the body is itself a class reference: that's the parent.
        _ => {
            if let Some(name) = class_expression_name(node, source) {
                bases.push(name);
            }
        }
    }
}

/// Collect parent class-type names reachable from a `class_type_binding` body
/// (`_simple_class_type`).
///
/// Grammar (VERIFIED via `dump_ml_t`): `class type t = object inherit u … end`
/// parses as
///   `class_body_type > inheritance_specification { class_type: class_type_path }`
/// i.e. the `inheritance_specification` clauses are DIRECT children of
/// `class_body_type` (there is no `object_type` wrapper for a `class type`).
///   - a direct `class_type_path` (`class type t = u`) — `u` is the parent.
fn collect_bases_from_class_type(node: &Node, source: &str, bases: &mut Vec<String>) {
    match node.kind() {
        // The `object … end` signature body — inherit clauses are direct
        // children. `object_type` is handled identically for robustness.
        "class_body_type" | "object_type" => {
            collect_inheritance_specs(node, source, bases)
        }
        _ => {
            if let Some(name) = class_type_name(node, source) {
                bases.push(name);
            }
        }
    }
}

/// Harvest `inheritance_specification` (`inherit <class_type>`) clauses that are
/// direct children of `parent` (a `class_body_type` / `object_type`).
fn collect_inheritance_specs(parent: &Node, source: &str, bases: &mut Vec<String>) {
    let mut cursor = parent.walk();
    for child in parent.children(&mut cursor) {
        if child.kind() == "inheritance_specification" {
            if let Some(ct) = child.child_by_field_name("class_type") {
                if let Some(name) = class_type_name(&ct, source) {
                    bases.push(name);
                }
            }
        }
    }
}

/// Resolve the class NAME from a `_class_expression`, descending through the
/// application / instantiation / type-annotation wrappers down to the
/// `class_path` that holds the `class_name`.
fn class_expression_name(node: &Node, source: &str) -> Option<String> {
    match node.kind() {
        // `Base` or `Mod.Base` → class_name is the last segment.
        "class_path" => child_of_kind(node, "class_name").and_then(|n| node_text(&n, source)),
        // `Base arg1 arg2` → the class is in field `class`.
        "class_application" => node
            .child_by_field_name("class")
            .and_then(|c| class_expression_name(&c, source)),
        // `['a] Base` → contains a class_path.
        "instantiated_class" => child_of_kind(node, "class_path")
            .and_then(|c| class_expression_name(&c, source)),
        // `(expr : type)` → unwrap to the inner class.
        "typed_class_expression" => node
            .child_by_field_name("class")
            .and_then(|c| class_expression_name(&c, source)),
        "parenthesized_class_expression" => {
            // Single inner class expression child.
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if let Some(name) = class_expression_name(&child, source) {
                    return Some(name);
                }
            }
            None
        }
        _ => None,
    }
}

/// Resolve the class-type NAME from a `_simple_class_type`.
fn class_type_name(node: &Node, source: &str) -> Option<String> {
    match node.kind() {
        // `u` or `Mod.u` → class_type_name is the last segment.
        "class_type_path" => {
            child_of_kind(node, "class_type_name").and_then(|n| node_text(&n, source))
        }
        // `['a] u` → contains a class_type_path.
        "instantiated_class_type" => {
            child_of_kind(node, "class_type_path").and_then(|c| class_type_name(&c, source))
        }
        _ => None,
    }
}

/// First direct child of `node` with the given `kind`.
fn child_of_kind<'a>(node: &Node<'a>, kind: &str) -> Option<Node<'a>> {
    let mut cursor = node.walk();
    let found = node.children(&mut cursor).find(|c| c.kind() == kind);
    found
}

/// UTF-8 text of a node, `None` on a decode error or empty result.
fn node_text(node: &Node, source: &str) -> Option<String> {
    node.utf8_text(source.as_bytes())
        .ok()
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn parse_and_extract(source: &str) -> Vec<InheritanceNode> {
        let pool = ParserPool::new();
        extract_classes(source, &PathBuf::from("test.ml"), &pool).unwrap()
    }

    #[test]
    fn test_simple_class_no_inherit() {
        let source = r#"
class counter = object
  val mutable n = 0
  method incr = ()
end
"#;
        let classes = parse_and_extract(source);
        let c = classes.iter().find(|c| c.name == "counter").unwrap();
        assert!(c.bases.is_empty());
    }

    /// inheritance-extends-vs-implements-ocaml-v1 (T3) char test:
    /// `class b = object inherit a ... end` -> b extends a.
    #[test]
    fn test_class_inherit_object_body() {
        let source = r#"
class a = object
  method foo = 1
end

class b = object
  inherit a
  method bar = 2
end
"#;
        let classes = parse_and_extract(source);
        let b = classes.iter().find(|c| c.name == "b").unwrap();
        assert!(
            b.bases.contains(&"a".to_string()),
            "b should inherit a, bases={:?}",
            b.bases
        );
        let idx = b.bases.iter().position(|x| x == "a").unwrap();
        assert_eq!(
            b.base_kind_at(idx),
            InheritanceKind::Extends,
            "OCaml inherit is Extends"
        );
    }

    #[test]
    fn test_class_inherit_with_args() {
        // `inherit common timeout proc []` — applied parent class.
        let source = r#"
class virtual common timeout = object
  method timeout = timeout
end

class process timeout = object
  inherit common timeout
  method run = ()
end
"#;
        let classes = parse_and_extract(source);
        let p = classes.iter().find(|c| c.name == "process").unwrap();
        assert!(
            p.bases.contains(&"common".to_string()),
            "process should inherit common (ignoring args), bases={:?}",
            p.bases
        );
    }

    #[test]
    fn test_class_alias_binding() {
        // `class libev_deprecated = libev ()` — instantiation alias.
        let source = r#"
class libev = object
  method iter = ()
end

class libev_deprecated = libev ()
"#;
        let classes = parse_and_extract(source);
        let dep = classes
            .iter()
            .find(|c| c.name == "libev_deprecated")
            .unwrap();
        assert!(
            dep.bases.contains(&"libev".to_string()),
            "alias binding should inherit libev, bases={:?}",
            dep.bases
        );
        let idx = dep.bases.iter().position(|x| x == "libev").unwrap();
        assert_eq!(dep.base_kind_at(idx), InheritanceKind::Extends);
    }

    #[test]
    fn test_class_type_inherit() {
        // `class type t = object inherit abstract ... end`.
        let source = r#"
class virtual abstract = object
  method virtual iter : unit
end

class type t = object
  inherit abstract
  method foo : int
end
"#;
        let classes = parse_and_extract(source);
        let t = classes.iter().find(|c| c.name == "t").unwrap();
        assert_eq!(t.interface, Some(true), "class type is the interface arm");
        assert!(
            t.bases.contains(&"abstract".to_string()),
            "class type t should inherit abstract, bases={:?}",
            t.bases
        );
        let idx = t.bases.iter().position(|x| x == "abstract").unwrap();
        assert_eq!(t.base_kind_at(idx), InheritanceKind::Extends);
    }

    #[test]
    fn test_polymorphic_class_inherit() {
        // `class ['a] bounded_push_impl = object inherit ['a] bounded_push ...`
        let source = r#"
class virtual ['a] bounded_push = object
  method virtual push : 'a -> unit
end

class ['a] bounded_push_impl = object
  inherit ['a] bounded_push
  val mutable count = 0
end
"#;
        let classes = parse_and_extract(source);
        let impl_cls = classes
            .iter()
            .find(|c| c.name == "bounded_push_impl")
            .unwrap();
        assert!(
            impl_cls.bases.contains(&"bounded_push".to_string()),
            "polymorphic inherit should resolve base name, bases={:?}",
            impl_cls.bases
        );
    }

    #[test]
    fn test_multiple_bindings_and_nested_module() {
        let source = r#"
module M = struct
  class base = object method m = () end
  class derived = object inherit base end
end
"#;
        let classes = parse_and_extract(source);
        assert!(classes.iter().any(|c| c.name == "base"));
        let d = classes.iter().find(|c| c.name == "derived").unwrap();
        assert!(d.bases.contains(&"base".to_string()));
    }

    #[test]
    fn test_no_phantom_method_type_bases() {
        // A class whose body references types in method signatures must not
        // turn those types into inheritance bases.
        let source = r#"
class worker = object
  method run : string -> int = fun _ -> 0
  method name : string = "w"
end
"#;
        let classes = parse_and_extract(source);
        let w = classes.iter().find(|c| c.name == "worker").unwrap();
        assert!(
            w.bases.is_empty(),
            "method signature types are not bases, got {:?}",
            w.bases
        );
    }
}
