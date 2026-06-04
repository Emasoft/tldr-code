//! Solidity contract extraction for inheritance analysis (v0.5.0 SOL-005c)
//!
//! Extracts `contract`, `interface`, and `library` declarations from
//! Solidity source code using tree-sitter-solidity 1.2.13.
//!
//! # Design
//!
//! Modeled on Java's `extract_java_class_bases` (per oracle research):
//! Solidity's `is A, B` inheritance list maps directly onto Java's
//! flattened "extends superclass + implements interfaces" model. Both
//! languages expose a single bases list per type declaration; both can
//! be walked with the same per-`inheritance_specifier`-child loop.
//!
//! For each top-level Solidity type declaration we emit one
//! [`InheritanceNode`]:
//! - `contract_declaration`   -> bases from `inheritance_specifier`
//!   children, `interface = None` (regular contract)
//! - `interface_declaration`  -> bases from `inheritance_specifier`
//!   children, `interface = Some(true)`
//! - `library_declaration`    -> libraries cannot inherit per the
//!   Solidity language spec, but we still emit the node so that the
//!   graph reports it for downstream consumers (e.g. uses-for relations
//!   in v2). Bases will be empty in practice; we still walk
//!   defensively in case grammar shape changes.
//!
//! # AST shape (tree-sitter-solidity 1.2.13)
//!
//! ```text
//! contract_declaration
//!   ├─ "contract"             (keyword)
//!   ├─ identifier              (contract name -- field "name")
//!   ├─ inheritance_specifier   (one PER ancestor, repeated)
//!   │    └─ ancestor: user_defined_type
//!   │         └─ identifier   (the base name, possibly member_expression)
//!   └─ contract_body
//! ```
//!
//! The `ancestor` field name and `user_defined_type` wrapper come
//! straight from the grammar (verified via `crates/tldr-core/src/ast/extract.rs`
//! `extract_solidity_class_bases` which uses the same shape).
//!
//! # Multiple inheritance / C3 linearization
//!
//! Solidity supports multiple inheritance with C3 linearization
//! (most-derived to least-derived order). For v1 we do NOT compute
//! the linearized MRO -- we preserve only the *declared* base order
//! (i.e. for `contract A is B, C`, the bases vec is `[B, C]` exactly
//! in source order). Downstream patterns/diamond detection in
//! `inheritance::patterns` already operates on the unordered graph;
//! a future SOL-005d milestone may add C3 linearization on top.

use std::path::Path;

use tree_sitter::{Node, Tree};

use crate::ast::parser::ParserPool;
use crate::types::{InheritanceNode, Language};
use crate::TldrResult;

/// Extract contract, interface, and library declarations from Solidity source.
pub fn extract_classes(
    source: &str,
    file_path: &Path,
    parser_pool: &ParserPool,
) -> TldrResult<Vec<InheritanceNode>> {
    let tree = parser_pool.parse(source, Language::Solidity)?;
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
        "contract_declaration" => {
            if let Some(class) = extract_contract(node, source, file_path) {
                classes.push(class);
            }
        }
        "interface_declaration" => {
            if let Some(iface) = extract_interface(node, source, file_path) {
                classes.push(iface);
            }
        }
        "library_declaration" => {
            if let Some(lib) = extract_library(node, source, file_path) {
                classes.push(lib);
            }
        }
        _ => {}
    }

    // Recurse for safety; Solidity does not nest contracts inside other
    // contracts per the language spec, but the AST walker pattern
    // (mirroring java.rs / kotlin.rs) keeps the recursion to handle any
    // future grammar additions and unusual top-level shapes (e.g.
    // `source_unit` wrapping).
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        visit_node(&child, source, file_path, classes);
    }
}

/// Extract a `contract_declaration` node.
///
/// Solidity grammar:
/// - `name` field -> identifier
/// - zero or more `inheritance_specifier` children for `is A, B`
/// - `abstract` keyword may appear as a direct child token preceding
///   the `contract` keyword (e.g. `abstract contract Foo is Bar { }`)
fn extract_contract(node: &Node, source: &str, file_path: &Path) -> Option<InheritanceNode> {
    let name_node = node.child_by_field_name("name")?;
    let name = name_node.utf8_text(source.as_bytes()).ok()?.to_string();

    let line = node.start_position().row as u32 + 1;
    let mut class_node =
        InheritanceNode::new(name, file_path.to_path_buf(), line, Language::Solidity);

    class_node.bases = extract_solidity_bases(node, source);

    if has_abstract_keyword(node, source) {
        class_node.is_abstract = Some(true);
    }

    Some(class_node)
}

/// Extract an `interface_declaration` node. Interfaces in Solidity
/// are implicitly abstract (no implementation) and can inherit only
/// from other interfaces. They follow the same `is A, B` syntax.
fn extract_interface(node: &Node, source: &str, file_path: &Path) -> Option<InheritanceNode> {
    let name_node = node.child_by_field_name("name")?;
    let name = name_node.utf8_text(source.as_bytes()).ok()?.to_string();

    let line = node.start_position().row as u32 + 1;
    let mut iface_node =
        InheritanceNode::new(name, file_path.to_path_buf(), line, Language::Solidity);
    iface_node.interface = Some(true);
    iface_node.bases = extract_solidity_bases(node, source);

    Some(iface_node)
}

/// Extract a `library_declaration` node. Libraries cannot inherit in
/// the Solidity language spec, but we still emit a node so they appear
/// in the inheritance report (with `bases = []`). We walk defensively
/// for `inheritance_specifier` children in case grammar shape changes.
fn extract_library(node: &Node, source: &str, file_path: &Path) -> Option<InheritanceNode> {
    let name_node = node.child_by_field_name("name")?;
    let name = name_node.utf8_text(source.as_bytes()).ok()?.to_string();

    let line = node.start_position().row as u32 + 1;
    let mut lib_node =
        InheritanceNode::new(name, file_path.to_path_buf(), line, Language::Solidity);
    lib_node.bases = extract_solidity_bases(node, source);

    Some(lib_node)
}

/// Flatten `is A, B` inheritance specifiers into a `Vec<String>` of
/// base names in declared source order.
///
/// Mirrors `extract_solidity_class_bases` in
/// `crates/tldr-core/src/ast/extract.rs` (SOL-003) but returns
/// the names independent of `FieldInfo`/`MethodInfo` structures.
///
/// Each `inheritance_specifier` has an `ancestor` field of kind
/// `user_defined_type` whose first identifier child is the base name.
/// We fall back to scanning for a `user_defined_type` direct child
/// when the field is absent (defensive against grammar revisions).
fn extract_solidity_bases(node: &Node, source: &str) -> Vec<String> {
    let mut bases = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() != "inheritance_specifier" {
            continue;
        }

        if let Some(ancestor) = child.child_by_field_name("ancestor") {
            if let Some(name) = user_defined_type_name(&ancestor, source) {
                bases.push(name);
                continue;
            }
        }

        // Fallback: scan for the first user_defined_type child directly.
        let mut ic = child.walk();
        for ichild in child.children(&mut ic) {
            if ichild.kind() == "user_defined_type" {
                if let Some(name) = user_defined_type_name(&ichild, source) {
                    bases.push(name);
                }
                break;
            }
        }
    }
    bases
}

/// Extract the bare identifier of a `user_defined_type` node. Most
/// Solidity inheritance bases are bare identifiers (`Ownable`). When
/// the base is namespaced (`OpenZeppelin.Ownable`, grammar emits a
/// `member_expression`) we surface the full dotted text. Falls back to
/// the whole-node text when neither child kind is present.
fn user_defined_type_name(node: &Node, source: &str) -> Option<String> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "identifier" => {
                return child
                    .utf8_text(source.as_bytes())
                    .ok()
                    .map(|s| s.to_string());
            }
            "member_expression" => {
                return child
                    .utf8_text(source.as_bytes())
                    .ok()
                    .map(|s| s.to_string());
            }
            _ => {}
        }
    }
    node.utf8_text(source.as_bytes())
        .ok()
        .map(|s| s.to_string())
}

/// Return `true` when an `abstract contract` declaration has the
/// `abstract` keyword as a direct child token. The Solidity grammar
/// places this as a sibling token before the `contract` keyword.
fn has_abstract_keyword(node: &Node, source: &str) -> bool {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "abstract" {
            return true;
        }
        // Some grammar versions emit the keyword as an anonymous token
        // whose text is "abstract". Check defensively.
        if !child.is_named() {
            if let Ok(text) = child.utf8_text(source.as_bytes()) {
                if text == "abstract" {
                    return true;
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn parse_and_extract(source: &str) -> Vec<InheritanceNode> {
        let pool = ParserPool::new();
        extract_classes(source, &PathBuf::from("Test.sol"), &pool).unwrap()
    }

    #[test]
    fn test_simple_contract_no_inheritance() {
        let src = r#"
pragma solidity ^0.8.0;
contract Foo {
    uint256 public x;
}
"#;
        let classes = parse_and_extract(src);
        assert_eq!(classes.len(), 1);
        assert_eq!(classes[0].name, "Foo");
        assert!(classes[0].bases.is_empty());
        assert_eq!(classes[0].language, Language::Solidity);
        assert_eq!(classes[0].interface, None);
        assert_eq!(classes[0].is_abstract, None);
    }

    #[test]
    fn test_contract_single_base() {
        let src = r#"
pragma solidity ^0.8.0;
contract Base {}
contract Child is Base {}
"#;
        let classes = parse_and_extract(src);
        assert_eq!(classes.len(), 2);
        let child = classes.iter().find(|c| c.name == "Child").unwrap();
        assert_eq!(child.bases, vec!["Base".to_string()]);
    }

    #[test]
    fn test_contract_multiple_bases_preserves_order() {
        let src = r#"
pragma solidity ^0.8.0;
contract B {}
contract C {}
contract A is B, C {}
"#;
        let classes = parse_and_extract(src);
        let a = classes.iter().find(|c| c.name == "A").unwrap();
        // Declared order MUST be preserved (no C3 linearization in v1).
        assert_eq!(a.bases, vec!["B".to_string(), "C".to_string()]);
    }

    #[test]
    fn test_interface_inheritance() {
        let src = r#"
pragma solidity ^0.8.0;
interface IFoo {}
interface IBar {}
contract X is IFoo, IBar {}
"#;
        let classes = parse_and_extract(src);
        let ifoo = classes.iter().find(|c| c.name == "IFoo").unwrap();
        assert_eq!(ifoo.interface, Some(true));
        let ibar = classes.iter().find(|c| c.name == "IBar").unwrap();
        assert_eq!(ibar.interface, Some(true));

        let x = classes.iter().find(|c| c.name == "X").unwrap();
        assert_eq!(x.bases, vec!["IFoo".to_string(), "IBar".to_string()]);
        assert_eq!(x.interface, None); // X is a contract, not interface
    }

    #[test]
    fn test_interface_extends_interface() {
        let src = r#"
pragma solidity ^0.8.0;
interface IBase {}
interface IDerived is IBase {}
"#;
        let classes = parse_and_extract(src);
        let derived = classes.iter().find(|c| c.name == "IDerived").unwrap();
        assert_eq!(derived.interface, Some(true));
        assert_eq!(derived.bases, vec!["IBase".to_string()]);
    }

    #[test]
    fn test_library_emitted_no_bases() {
        let src = r#"
pragma solidity ^0.8.0;
library SafeMath {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        return a + b;
    }
}
"#;
        let classes = parse_and_extract(src);
        assert_eq!(classes.len(), 1);
        assert_eq!(classes[0].name, "SafeMath");
        assert!(classes[0].bases.is_empty());
    }

    #[test]
    fn test_abstract_contract() {
        let src = r#"
pragma solidity ^0.8.0;
abstract contract Base {
    function foo() public virtual;
}
contract Impl is Base {
    function foo() public override {}
}
"#;
        let classes = parse_and_extract(src);
        let base = classes.iter().find(|c| c.name == "Base").unwrap();
        assert_eq!(base.is_abstract, Some(true));
        let impl_c = classes.iter().find(|c| c.name == "Impl").unwrap();
        assert_eq!(impl_c.is_abstract, None);
        assert_eq!(impl_c.bases, vec!["Base".to_string()]);
    }

    #[test]
    fn test_diamond_pattern() {
        // Classic diamond: A is B,C ; B is D ; C is D
        let src = r#"
pragma solidity ^0.8.0;
contract D {}
contract B is D {}
contract C is D {}
contract A is B, C {}
"#;
        let classes = parse_and_extract(src);
        assert_eq!(classes.len(), 4);
        let a = classes.iter().find(|c| c.name == "A").unwrap();
        assert_eq!(a.bases, vec!["B".to_string(), "C".to_string()]);
        let b = classes.iter().find(|c| c.name == "B").unwrap();
        assert_eq!(b.bases, vec!["D".to_string()]);
        let c_node = classes.iter().find(|c| c.name == "C").unwrap();
        assert_eq!(c_node.bases, vec!["D".to_string()]);
        let d = classes.iter().find(|c| c.name == "D").unwrap();
        assert!(d.bases.is_empty());
    }

    #[test]
    fn test_inheritance_with_constructor_args() {
        // Constructor-args on a base in the inheritance list must NOT
        // leak into the name; only the bare base identifier is captured.
        let src = r#"
pragma solidity ^0.8.0;
contract Base {
    constructor(uint256 x) {}
}
contract Child is Base(42) {}
"#;
        let classes = parse_and_extract(src);
        let child = classes.iter().find(|c| c.name == "Child").unwrap();
        assert_eq!(child.bases, vec!["Base".to_string()]);
    }

    #[test]
    fn test_line_numbers_recorded() {
        let src = "pragma solidity ^0.8.0;\ncontract Foo {}\ncontract Bar is Foo {}\n";
        let classes = parse_and_extract(src);
        let foo = classes.iter().find(|c| c.name == "Foo").unwrap();
        let bar = classes.iter().find(|c| c.name == "Bar").unwrap();
        assert_eq!(foo.line, 2);
        assert_eq!(bar.line, 3);
    }

    #[test]
    fn test_file_path_recorded() {
        let pool = ParserPool::new();
        let src = "contract Foo {}";
        let path = PathBuf::from("contracts/Foo.sol");
        let classes = extract_classes(src, &path, &pool).unwrap();
        assert_eq!(classes.len(), 1);
        assert_eq!(classes[0].file, path);
    }
}
