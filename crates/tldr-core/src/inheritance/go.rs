//! Go struct embedding extraction (A14)
//!
//! Go doesn't have class inheritance, but uses struct embedding for composition.
//! This module extracts embedded structs and models them as "Embeds" edges.
//!
//! Example:
//! ```go
//! type Animal struct {
//!     Name string
//! }
//!
//! type Dog struct {
//!     Animal      // Embedded - acts like inheritance
//!     Breed string
//! }
//! ```

use std::path::Path;

use tree_sitter::{Node, Tree};

use crate::ast::parser::ParserPool;
use crate::types::{InheritanceKind, InheritanceNode, Language};
use crate::TldrResult;

/// Extract struct definitions with embedded types from Go source code
pub fn extract_classes(
    source: &str,
    file_path: &Path,
    parser_pool: &ParserPool,
) -> TldrResult<Vec<InheritanceNode>> {
    let tree = parser_pool.parse(source, Language::Go)?;
    let mut classes = Vec::new();

    extract_type_declarations(&tree, source, file_path, &mut classes);

    Ok(classes)
}

fn extract_type_declarations(
    tree: &Tree,
    source: &str,
    file_path: &Path,
    classes: &mut Vec<InheritanceNode>,
) {
    let root = tree.root_node();
    visit_node(&root, source, file_path, classes);
}

fn visit_node(node: &Node, source: &str, file_path: &Path, classes: &mut Vec<InheritanceNode>) {
    if node.kind() == "type_declaration" {
        // type_declaration contains type_spec children
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "type_spec" {
                    if let Some(class) = extract_type_spec(&child, source, file_path) {
                        classes.push(class);
                    }
                }
            }
        }
    }

    // Recurse into children
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        visit_node(&child, source, file_path, classes);
    }
}

fn extract_type_spec(node: &Node, source: &str, file_path: &Path) -> Option<InheritanceNode> {
    // Get type name
    let name_node = node.child_by_field_name("name")?;
    let name = name_node.utf8_text(source.as_bytes()).ok()?.to_string();

    let line = node.start_position().row as u32 + 1;

    // Get the type definition
    let type_node = node.child_by_field_name("type")?;

    // Only process struct types
    if type_node.kind() != "struct_type" {
        // For interfaces, we could model them separately
        if type_node.kind() == "interface_type" {
            let mut iface = InheritanceNode::new(name, file_path.to_path_buf(), line, Language::Go);
            iface.interface = Some(true);

            // Extract embedded interfaces. inheritance-extends-vs-implements
            // (T3): an interface embedding another interface is interface
            // composition — an `extends`-style relationship (the embedded
            // interface's method set becomes part of this one), NOT struct
            // composition. Tag every embed `Extends`.
            let bases = extract_interface_embeds(&type_node, source);
            let kinds = vec![InheritanceKind::Extends; bases.len()];
            iface.bases = bases;
            if !kinds.is_empty() {
                iface.base_kinds = Some(kinds);
            }

            return Some(iface);
        }
        return None;
    }

    let mut class_node = InheritanceNode::new(name, file_path.to_path_buf(), line, Language::Go);

    // Extract embedded structs (anonymous fields). inheritance-extends-vs-
    // implements (T3): Go struct embedding is COMPOSITION, not class
    // inheritance (A14) — surface it as `Embeds`, not the default `Extends`.
    let bases = extract_struct_embeds(&type_node, source);
    let kinds = vec![InheritanceKind::Embeds; bases.len()];
    class_node.bases = bases;
    if !kinds.is_empty() {
        class_node.base_kinds = Some(kinds);
    }

    Some(class_node)
}

/// Extract embedded structs from struct type
/// Embedded fields are anonymous (no name, just type)
fn extract_struct_embeds(struct_node: &Node, source: &str) -> Vec<String> {
    let mut embeds = Vec::new();

    // Look for field_declaration_list
    for i in 0..struct_node.child_count() {
        if let Some(child) = struct_node.child(i) {
            if child.kind() == "field_declaration_list" {
                for j in 0..child.child_count() {
                    if let Some(field) = child.child(j) {
                        if field.kind() == "field_declaration" {
                            if let Some(embed) = extract_embed_from_field(&field, source) {
                                embeds.push(embed);
                            }
                        }
                    }
                }
            }
        }
    }

    embeds
}

/// Extract embedded type from field declaration
/// An embedded field has a type but no name
fn extract_embed_from_field(field: &Node, source: &str) -> Option<String> {
    // Check if this is an embedded field (no name, just type)
    // In tree-sitter-go, embedded fields have the type as the first significant child

    let mut has_name = false;
    let mut type_name = None;

    for i in 0..field.child_count() {
        if let Some(child) = field.child(i) {
            match child.kind() {
                "field_identifier" => {
                    has_name = true;
                }
                "type_identifier" => {
                    type_name = child
                        .utf8_text(source.as_bytes())
                        .ok()
                        .map(|s| s.to_string());
                }
                "pointer_type" => {
                    // *EmbeddedType
                    if let Some(inner) = child.child_by_field_name("type") {
                        if inner.kind() == "type_identifier" {
                            type_name = inner
                                .utf8_text(source.as_bytes())
                                .ok()
                                .map(|s| s.to_string());
                        }
                    }
                }
                "qualified_type" => {
                    // package.Type
                    if let Some(name) = child.child_by_field_name("name") {
                        type_name = name
                            .utf8_text(source.as_bytes())
                            .ok()
                            .map(|s| s.to_string());
                    }
                }
                _ => {}
            }
        }
    }

    // Only return if it's an embedded field (no explicit name)
    if !has_name {
        type_name
    } else {
        None
    }
}

/// Extract embedded interfaces from an `interface_type` body.
///
/// inheritance-extends-vs-implements (T3): the previous implementation
/// recursed into EVERY child of the interface body and harvested every
/// `type_identifier` / `qualified_type` it saw. In the current
/// tree-sitter-go grammar an interface body is a list of:
///   - `type_elem`   — an EMBEDDED interface (`io.Reader`, `Reader`), and
///   - `method_elem` — a METHOD signature (`Read(p []byte) (int, error)`).
/// Recursing into `method_elem` grabbed the parameter/return types
/// (`error`, `int`, `string`, `byte`, `any`, …) as if they were embedded
/// interfaces, which is exactly the go-gin "46/90 edges wrong" bug:
/// `Core -> error`, `Encoder -> bool`, `Decoder -> any` etc.
///
/// The fix is AST-driven: harvest types ONLY from `type_elem` children and
/// NEVER descend into `method_elem`. A `type_elem` wraps a single type
/// (`type_identifier`, `qualified_type`, or a generic `generic_type`).
fn extract_interface_embeds(iface_node: &Node, source: &str) -> Vec<String> {
    let mut embeds = Vec::new();

    let mut cursor = iface_node.walk();
    for child in iface_node.children(&mut cursor) {
        match child.kind() {
            // Embedded interface element — the ONLY place an embedded
            // interface name lives in the current grammar.
            "type_elem" => {
                collect_type_elem_names(&child, source, &mut embeds);
            }
            // Older grammar shape (defensive): an embedded type can appear
            // as a bare `type_identifier` / `qualified_type` directly under
            // the interface body. Methods are `method_elem` / `method_spec`
            // and are intentionally NOT matched here.
            "type_identifier" => {
                if let Ok(name) = child.utf8_text(source.as_bytes()) {
                    embeds.push(name.to_string());
                }
            }
            "qualified_type" => {
                if let Some(name) = qualified_type_name(&child, source) {
                    embeds.push(name);
                }
            }
            // `method_elem` / `method_spec` / braces / comments: skip. Method
            // signatures are NOT inheritance.
            _ => {}
        }
    }

    embeds
}

/// Collect the embedded-type name(s) from a single `type_elem` node.
///
/// A `type_elem` normally wraps exactly one type. We accept the simple
/// named forms (`type_identifier`, `qualified_type`, `generic_type`); type
/// SETS / unions (`~int | ~string`, used in generic constraints) carry no
/// embedded-interface semantics and are ignored.
fn collect_type_elem_names(type_elem: &Node, source: &str, embeds: &mut Vec<String>) {
    let mut cursor = type_elem.walk();
    for child in type_elem.children(&mut cursor) {
        match child.kind() {
            "type_identifier" => {
                if let Ok(name) = child.utf8_text(source.as_bytes()) {
                    embeds.push(name.to_string());
                }
            }
            "qualified_type" => {
                if let Some(name) = qualified_type_name(&child, source) {
                    embeds.push(name);
                }
            }
            "generic_type" => {
                // `Constraint[T]` embedded — keep the base type name.
                if let Some(inner) = child.child_by_field_name("type") {
                    match inner.kind() {
                        "type_identifier" => {
                            if let Ok(name) = inner.utf8_text(source.as_bytes()) {
                                embeds.push(name.to_string());
                            }
                        }
                        "qualified_type" => {
                            if let Some(name) = qualified_type_name(&inner, source) {
                                embeds.push(name);
                            }
                        }
                        _ => {}
                    }
                }
            }
            // Type-set elements (`~int`, `int | string`) and punctuation are
            // not embedded interfaces.
            _ => {}
        }
    }
}

/// Extract the type name from a `qualified_type` (`pkg.Type` -> `Type`).
fn qualified_type_name(node: &Node, source: &str) -> Option<String> {
    node.child_by_field_name("name")
        .and_then(|n| n.utf8_text(source.as_bytes()).ok())
        .map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn parse_and_extract(source: &str) -> Vec<InheritanceNode> {
        let pool = ParserPool::new();
        extract_classes(source, &PathBuf::from("test.go"), &pool).unwrap()
    }

    #[test]
    fn test_simple_struct() {
        let source = r#"
package main

type Animal struct {
    Name string
}
"#;
        let classes = parse_and_extract(source);
        assert_eq!(classes.len(), 1);
        assert_eq!(classes[0].name, "Animal");
        assert!(classes[0].bases.is_empty());
    }

    #[test]
    fn test_struct_embedding() {
        let source = r#"
package main

type Animal struct {
    Name string
}

type Dog struct {
    Animal
    Breed string
}
"#;
        let classes = parse_and_extract(source);
        assert_eq!(classes.len(), 2);

        let dog = classes.iter().find(|c| c.name == "Dog").unwrap();
        assert!(dog.bases.contains(&"Animal".to_string()));
    }

    /// inheritance-extends-vs-implements (T3): Go struct embedding is
    /// COMPOSITION, so the edge kind must be `Embeds`, never the default
    /// `Extends`. Guards the regression where every Go base defaulted to
    /// `Extends`.
    #[test]
    fn test_struct_embed_kind_is_embeds() {
        let source = r#"
package main

type Animal struct { Name string }

type Dog struct {
    Animal
    Breed string
}
"#;
        let classes = parse_and_extract(source);
        let dog = classes.iter().find(|c| c.name == "Dog").unwrap();
        let idx = dog.bases.iter().position(|b| b == "Animal").unwrap();
        assert_eq!(
            dog.base_kind_at(idx),
            InheritanceKind::Embeds,
            "Go struct embedding must be Embeds (composition), not {:?}",
            dog.base_kind_at(idx)
        );
    }

    #[test]
    fn test_multiple_embedding() {
        let source = r#"
package main

type Walker struct {}
type Talker struct {}

type Robot struct {
    Walker
    Talker
    ID int
}
"#;
        let classes = parse_and_extract(source);
        let robot = classes.iter().find(|c| c.name == "Robot").unwrap();
        assert!(robot.bases.contains(&"Walker".to_string()));
        assert!(robot.bases.contains(&"Talker".to_string()));
    }

    #[test]
    fn test_interface() {
        let source = r#"
package main

type Reader interface {
    Read(p []byte) (n int, err error)
}
"#;
        let classes = parse_and_extract(source);
        assert_eq!(classes.len(), 1);
        assert_eq!(classes[0].name, "Reader");
        assert_eq!(classes[0].interface, Some(true));
    }

    /// inheritance-extends-vs-implements (T3) — go-gin root cause. A method
    /// signature's parameter/return types (`error`, `int`, `string`, `byte`,
    /// `any`) are NOT embedded interfaces and must never become inheritance
    /// bases. Before the `type_elem`/`method_elem` distinction this interface
    /// emitted `Reader -> error`, `Reader -> int`, etc.
    #[test]
    fn test_interface_method_signature_types_are_not_bases() {
        let source = r#"
package main

type Render interface {
    Render(http.ResponseWriter) error
    WriteContentType(w http.ResponseWriter)
    Status() int
    WriteString(string) (int, error)
}
"#;
        let classes = parse_and_extract(source);
        let render = classes.iter().find(|c| c.name == "Render").unwrap();
        assert_eq!(render.interface, Some(true));
        for noise in ["error", "int", "string", "any", "byte", "bool"] {
            assert!(
                !render.bases.contains(&noise.to_string()),
                "method-signature type {:?} must not be an inheritance base; bases={:?}",
                noise,
                render.bases
            );
        }
        // A pure-method interface embeds nothing.
        assert!(
            render.bases.is_empty(),
            "interface with only methods has no embeds, got {:?}",
            render.bases
        );
    }

    #[test]
    fn test_interface_embedding() {
        let source = r#"
package main

type Reader interface {
    Read(p []byte) (n int, err error)
}

type Writer interface {
    Write(p []byte) (n int, err error)
}

type ReadWriter interface {
    Reader
    Writer
}
"#;
        let classes = parse_and_extract(source);
        let rw = classes.iter().find(|c| c.name == "ReadWriter").unwrap();
        assert_eq!(rw.interface, Some(true));
        assert!(rw.bases.contains(&"Reader".to_string()));
        assert!(rw.bases.contains(&"Writer".to_string()));
    }

    /// inheritance-extends-vs-implements (T3): an interface that BOTH embeds
    /// other interfaces AND declares methods must keep the embeds (tagged
    /// `Extends`) and drop the method-signature types. Mirrors gin's
    /// `ResponseWriter` (embeds `http.ResponseWriter` etc. + own methods).
    #[test]
    fn test_interface_embed_with_methods_keeps_only_embeds() {
        let source = r#"
package main

type ResponseWriter interface {
    http.ResponseWriter
    http.Hijacker
    Status() int
    WriteString(string) (int, error)
}
"#;
        let classes = parse_and_extract(source);
        let rw = classes.iter().find(|c| c.name == "ResponseWriter").unwrap();
        // Embedded interfaces present (qualified -> last segment).
        assert!(rw.bases.contains(&"ResponseWriter".to_string()));
        assert!(rw.bases.contains(&"Hijacker".to_string()));
        // Method-signature noise absent.
        assert!(!rw.bases.contains(&"int".to_string()));
        assert!(!rw.bases.contains(&"error".to_string()));
        assert!(!rw.bases.contains(&"string".to_string()));
        // Every embed is Extends (interface composition), not Embeds.
        for (i, _b) in rw.bases.iter().enumerate() {
            assert_eq!(rw.base_kind_at(i), InheritanceKind::Extends);
        }
    }

    /// inheritance-extends-vs-implements (T3): interface-to-interface
    /// embedding is `Extends`, distinct from struct `Embeds`.
    #[test]
    fn test_interface_embed_kind_is_extends() {
        let source = r#"
package main

type Reader interface { Read() }
type Writer interface { Write() }

type ReadWriter interface {
    Reader
    Writer
}
"#;
        let classes = parse_and_extract(source);
        let rw = classes.iter().find(|c| c.name == "ReadWriter").unwrap();
        let idx = rw.bases.iter().position(|b| b == "Reader").unwrap();
        assert_eq!(rw.base_kind_at(idx), InheritanceKind::Extends);
    }
}
