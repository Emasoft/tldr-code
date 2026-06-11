//! TypeScript/JavaScript class extraction
//!
//! Extracts class and interface definitions from TypeScript source code using tree-sitter.
//! Handles:
//! - Class inheritance (extends)
//! - Interface implementation (implements)
//! - Abstract classes
//! - Interface declarations
//! - Mixin patterns via class expressions (A13)

use std::path::Path;

use tree_sitter::{Node, Tree};

use crate::ast::parser::ParserPool;
use crate::types::{InheritanceKind, InheritanceNode, Language};
use crate::TldrResult;

/// Extract class and interface definitions from TypeScript source code
pub fn extract_classes(
    source: &str,
    file_path: &Path,
    parser_pool: &ParserPool,
) -> TldrResult<Vec<InheritanceNode>> {
    let tree = parser_pool.parse(source, Language::TypeScript)?;
    let mut classes = Vec::new();

    extract_declarations(&tree, source, file_path, &mut classes);

    Ok(classes)
}

fn extract_declarations(
    tree: &Tree,
    source: &str,
    file_path: &Path,
    classes: &mut Vec<InheritanceNode>,
) {
    let root = tree.root_node();
    visit_node(&root, source, file_path, classes);
}

fn visit_node(node: &Node, source: &str, file_path: &Path, classes: &mut Vec<InheritanceNode>) {
    match node.kind() {
        "class_declaration" => {
            if let Some(class) = extract_class(node, source, file_path, false) {
                classes.push(class);
            }
        }
        "abstract_class_declaration" => {
            if let Some(class) = extract_class(node, source, file_path, true) {
                classes.push(class);
            }
        }
        "interface_declaration" => {
            if let Some(iface) = extract_interface(node, source, file_path) {
                classes.push(iface);
            }
        }
        _ => {}
    }

    // Recurse into children
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        visit_node(&child, source, file_path, classes);
    }
}

fn extract_class(
    node: &Node,
    source: &str,
    file_path: &Path,
    is_abstract: bool,
) -> Option<InheritanceNode> {
    // Get class name
    let name_node = node.child_by_field_name("name")?;
    let name = name_node.utf8_text(source.as_bytes()).ok()?.to_string();

    let line = node.start_position().row as u32 + 1;

    let mut class_node = InheritanceNode::new(
        name.clone(),
        file_path.to_path_buf(),
        line,
        Language::TypeScript,
    );

    if is_abstract {
        class_node.is_abstract = Some(true);
    }

    // Extract from class_heritage (extends/implements).
    // cl11-implements-v1 (#82): track the per-base InheritanceKind in a
    // vector parallel to `bases` so `extends SuperClass` (Extends) is not
    // collapsed onto `implements Interface` (Implements) at edge-build time.
    let mut bases = Vec::new();
    let mut kinds = Vec::new();

    // Find heritage clauses - look for class_heritage node
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if child.kind() == "class_heritage" {
                extract_heritage_clauses(&child, source, &mut bases, &mut kinds);
            }
        }
    }

    debug_assert_eq!(bases.len(), kinds.len());
    class_node.bases = bases;
    if !kinds.is_empty() {
        class_node.base_kinds = Some(kinds);
    }

    Some(class_node)
}

fn extract_interface(node: &Node, source: &str, file_path: &Path) -> Option<InheritanceNode> {
    // Get interface name
    let name_node = node.child_by_field_name("name")?;
    let name = name_node.utf8_text(source.as_bytes()).ok()?.to_string();

    let line = node.start_position().row as u32 + 1;

    let mut iface_node = InheritanceNode::new(
        name.clone(),
        file_path.to_path_buf(),
        line,
        Language::TypeScript,
    );
    iface_node.interface = Some(true);

    // Extract extends for interfaces.
    // cl11-implements-v1 (#82): an interface extending another interface is
    // an `extends` relationship (Extends), not `implements`. Tag explicitly
    // so the parallel base_kinds vector stays consistent with classes.
    let mut bases = Vec::new();
    let mut kinds = Vec::new();

    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            // Interface uses extends_clause for inheritance
            if child.kind() == "extends_type_clause" {
                extract_type_list(&child, source, &mut bases, &mut kinds, InheritanceKind::Extends);
            }
        }
    }

    debug_assert_eq!(bases.len(), kinds.len());
    iface_node.bases = bases;
    if !kinds.is_empty() {
        iface_node.base_kinds = Some(kinds);
    }

    Some(iface_node)
}

/// Walk a `class_heritage` node, dispatching on the AST clause kind to tag
/// each base with the correct `InheritanceKind`.
///
/// cl11-implements-v1 (#82): the tree-sitter grammar already distinguishes
/// `extends_clause` from `implements_clause`; we propagate that distinction
/// into `kinds` (parallel to `bases`) instead of letting everything default
/// to `Extends` downstream.
fn extract_heritage_clauses(
    node: &Node,
    source: &str,
    bases: &mut Vec<String>,
    kinds: &mut Vec<InheritanceKind>,
) {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            match child.kind() {
                "extends_clause" => {
                    // extends SuperClass
                    extract_type_from_clause(&child, source, bases, kinds, InheritanceKind::Extends);
                }
                "implements_clause" => {
                    // implements Interface1, Interface2
                    extract_type_list(&child, source, bases, kinds, InheritanceKind::Implements);
                }
                _ => {}
            }
        }
    }
}

fn extract_type_from_clause(
    node: &Node,
    source: &str,
    bases: &mut Vec<String>,
    kinds: &mut Vec<InheritanceKind>,
    kind: InheritanceKind,
) {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if let Some(name) = extract_type_name(&child, source) {
                bases.push(name);
                kinds.push(kind);
            }
        }
    }
}

fn extract_type_list(
    node: &Node,
    source: &str,
    bases: &mut Vec<String>,
    kinds: &mut Vec<InheritanceKind>,
    kind: InheritanceKind,
) {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if let Some(name) = extract_type_name(&child, source) {
                bases.push(name);
                kinds.push(kind);
            }
        }
    }
}

fn extract_type_name(node: &Node, source: &str) -> Option<String> {
    match node.kind() {
        "type_identifier" | "identifier" => node
            .utf8_text(source.as_bytes())
            .ok()
            .map(|s| s.to_string()),
        "generic_type" => {
            // Generic<T> -> "Generic"
            let name = node.child_by_field_name("name")?;
            name.utf8_text(source.as_bytes())
                .ok()
                .map(|s| s.to_string())
        }
        "member_expression" => {
            // namespace.Type -> "Type"
            let prop = node.child_by_field_name("property")?;
            prop.utf8_text(source.as_bytes())
                .ok()
                .map(|s| s.to_string())
        }
        "call_expression" => {
            // Mixin(Base) -> extract "Mixin" as mixin pattern (A13)
            let func = node.child_by_field_name("function")?;
            extract_type_name(&func, source)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn parse_and_extract(source: &str) -> Vec<InheritanceNode> {
        let pool = ParserPool::new();
        extract_classes(source, &PathBuf::from("test.ts"), &pool).unwrap()
    }

    #[test]
    fn test_simple_class() {
        let source = r#"
class Animal {
    speak(): string {
        return "...";
    }
}
"#;
        let classes = parse_and_extract(source);
        assert_eq!(classes.len(), 1);
        assert_eq!(classes[0].name, "Animal");
        assert!(classes[0].bases.is_empty());
    }

    #[test]
    fn test_class_extends() {
        let source = r#"
class Animal {}

class Dog extends Animal {
    speak(): string {
        return "woof";
    }
}
"#;
        let classes = parse_and_extract(source);
        assert_eq!(classes.len(), 2);

        let dog = classes.iter().find(|c| c.name == "Dog").unwrap();
        assert!(dog.bases.contains(&"Animal".to_string()));
    }

    #[test]
    fn test_class_implements() {
        let source = r#"
interface Serializable {
    serialize(): string;
}

class Dog implements Serializable {
    serialize(): string {
        return "{}";
    }
}
"#;
        let classes = parse_and_extract(source);
        assert_eq!(classes.len(), 2);

        let serializable = classes.iter().find(|c| c.name == "Serializable").unwrap();
        assert_eq!(serializable.interface, Some(true));

        let dog = classes.iter().find(|c| c.name == "Dog").unwrap();
        assert!(dog.bases.contains(&"Serializable".to_string()));
    }

    #[test]
    fn test_abstract_class() {
        let source = r#"
abstract class Animal {
    abstract speak(): string;
}
"#;
        let classes = parse_and_extract(source);
        assert_eq!(classes.len(), 1);
        assert_eq!(classes[0].name, "Animal");
        assert_eq!(classes[0].is_abstract, Some(true));
    }

    #[test]
    fn test_multiple_implements() {
        let source = r#"
interface Serializable {
    serialize(): string;
}

interface Walkable {
    walk(): void;
}

class Cat extends Animal implements Serializable, Walkable {
}
"#;
        let classes = parse_and_extract(source);
        let cat = classes.iter().find(|c| c.name == "Cat").unwrap();
        assert!(cat.bases.contains(&"Animal".to_string()));
        assert!(cat.bases.contains(&"Serializable".to_string()));
        assert!(cat.bases.contains(&"Walkable".to_string()));
    }

    #[test]
    fn test_interface_extends() {
        let source = r#"
interface Base {
    id: number;
}

interface Extended extends Base {
    name: string;
}
"#;
        let classes = parse_and_extract(source);
        let extended = classes.iter().find(|c| c.name == "Extended").unwrap();
        assert_eq!(extended.interface, Some(true));
        assert!(extended.bases.contains(&"Base".to_string()));
    }
}
