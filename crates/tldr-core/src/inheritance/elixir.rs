//! Elixir inheritance walker.
//!
//! inheritance-walker-per-lang-v1 (M-039): extracts inheritance/conformance
//! relationships from Elixir source.
//!
//! Recognized constructs:
//!
//! | Construct                            | Edge / semantics                  |
//! |--------------------------------------|-----------------------------------|
//! | `defprotocol P do … end`             | Node `P` (protocol/interface)     |
//! | `defimpl P, for: T do … end`         | Edge T -> P (implements)          |
//! | `defmodule M do … end`               | Node `M`                          |
//! | `use Mod`                            | Edge M -> Mod (extends)           |
//! | `@behaviour B`                       | Edge M -> B (implements)          |
//!
//! Elixir has no classical class inheritance; conformance to protocols
//! and behaviours plus the `use` macro injection model is what we
//! surface as inheritance edges.

use std::path::Path;

use tree_sitter::Node;

use crate::ast::parser::ParserPool;
use crate::types::{InheritanceKind, InheritanceNode, Language};
use crate::TldrResult;

/// Extract Elixir modules and protocols, plus conformance edges from
/// `defimpl ... for: T`, `use Mod`, and `@behaviour B`.
pub fn extract_classes(
    source: &str,
    file_path: &Path,
    parser_pool: &ParserPool,
) -> TldrResult<Vec<InheritanceNode>> {
    let tree = parser_pool.parse(source, Language::Elixir)?;
    let mut classes: Vec<InheritanceNode> = Vec::new();

    let root = tree.root_node();
    visit_node(&root, source, file_path, &mut classes);

    Ok(classes)
}

fn visit_node(
    node: &Node,
    source: &str,
    file_path: &Path,
    classes: &mut Vec<InheritanceNode>,
) {
    if node.kind() == "call" {
        if let Some(call_name) = call_identifier_name(node, source) {
            match call_name.as_str() {
                "defmodule" => {
                    if let Some(class_node) = extract_defmodule(node, source, file_path) {
                        classes.push(class_node);
                    }
                    // Nested defmodules are picked up by the recursion
                    // below.
                }
                "defprotocol" => {
                    if let Some(class_node) = extract_defprotocol(node, source, file_path) {
                        classes.push(class_node);
                    }
                }
                "defimpl" => {
                    if let Some(class_node) = extract_defimpl(node, source, file_path) {
                        classes.push(class_node);
                    }
                }
                _ => {}
            }
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        visit_node(&child, source, file_path, classes);
    }
}

/// Get the first identifier child of a `call` node, which is the macro
/// or function being invoked (e.g. "defmodule", "use", "defimpl").
fn call_identifier_name(node: &Node, source: &str) -> Option<String> {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if child.kind() == "identifier" {
                return child.utf8_text(source.as_bytes()).ok().map(|s| s.to_string());
            }
        }
    }
    None
}

/// Extract the first alias argument from a `call` node — that's the
/// module/protocol name in `defmodule X`, `defprotocol X`,
/// `use X`, `@behaviour X`.
fn first_alias_arg(node: &Node, source: &str) -> Option<String> {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if child.kind() == "arguments" {
                for j in 0..child.child_count() {
                    if let Some(arg) = child.child(j) {
                        if arg.kind() == "alias" || arg.kind() == "dot" {
                            return arg
                                .utf8_text(source.as_bytes())
                                .ok()
                                .map(|s| s.to_string());
                        }
                    }
                }
            }
        }
    }
    None
}

/// Look up a keyword value in an Elixir call's keyword arguments.
///
/// Returns the alias/dot text for `key: AliasName` when the call's
/// `arguments` contain a `keywords` node with a pair whose key matches
/// `key`. Used for `defimpl Proto, for: TypeName`.
///
/// AST shape (tree-sitter-elixir):
/// ```text
/// (arguments
///   (alias "MyProto")
///   ","
///   (keywords
///     (pair
///       (keyword "for: ")
///       (alias "MyType"))))
/// ```
/// `pair` does NOT expose `key`/`value` field names — we identify them
/// positionally: first named child is the `keyword`, the next non-comma
/// named child is the value.
fn lookup_keyword_alias(node: &Node, source: &str, key: &str) -> Option<String> {
    for i in 0..node.child_count() {
        let arg_list = match node.child(i) {
            Some(n) => n,
            None => continue,
        };
        if arg_list.kind() != "arguments" {
            continue;
        }
        for j in 0..arg_list.child_count() {
            let kw = match arg_list.child(j) {
                Some(n) => n,
                None => continue,
            };
            if kw.kind() != "keywords" {
                continue;
            }
            for k in 0..kw.child_count() {
                let pair = match kw.child(k) {
                    Some(n) => n,
                    None => continue,
                };
                if pair.kind() != "pair" {
                    continue;
                }
                // Collect named children of the pair: typically
                // `[keyword, alias|dot|…]`.
                let mut named: Vec<Node> = Vec::new();
                let mut pc = pair.walk();
                for c in pair.children(&mut pc) {
                    if c.is_named() {
                        named.push(c);
                    }
                }
                if named.len() < 2 {
                    continue;
                }
                let key_node = named[0];
                if key_node.kind() != "keyword" {
                    continue;
                }
                let key_txt = match key_node.utf8_text(source.as_bytes()) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                // tree-sitter-elixir surfaces the key text as
                // `"for: "` (trailing colon then space). Normalize by
                // trimming whitespace first, then trailing colons.
                let key_clean = key_txt.trim().trim_end_matches(':');
                if key_clean != key {
                    continue;
                }
                let val_node = named[1];
                if val_node.kind() == "alias" || val_node.kind() == "dot" {
                    return val_node
                        .utf8_text(source.as_bytes())
                        .ok()
                        .map(|s| s.to_string());
                }
            }
        }
    }
    None
}

/// Extract a `defmodule M do ... end` definition. The module body is
/// scanned for `use Mod` and `@behaviour Mod` declarations which
/// contribute inheritance/conformance bases to the module node.
fn extract_defmodule(
    node: &Node,
    source: &str,
    file_path: &Path,
) -> Option<InheritanceNode> {
    let name = first_alias_arg(node, source)?;
    let line = node.start_position().row as u32 + 1;
    let mut module = InheritanceNode::new(name, file_path.to_path_buf(), line, Language::Elixir);

    if let Some(block) = find_do_block(node) {
        collect_use_and_behaviour(&block, source, &mut module);
    }

    Some(module)
}

/// Find the `do_block` child of a `call` (the module / protocol body).
fn find_do_block<'a>(node: &Node<'a>) -> Option<Node<'a>> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "do_block" {
            return Some(child);
        }
        if child.kind() == "arguments" {
            let mut ac = child.walk();
            for arg_child in child.children(&mut ac) {
                if arg_child.kind() == "do_block" {
                    return Some(arg_child);
                }
            }
        }
    }
    None
}

/// Scan a do-block for `use Mod` and `@behaviour Mod` statements,
/// appending each as a base on `module`. `use` is treated as `extends`
/// (the macro injects implementation), `@behaviour` is `implements`.
///
/// Nested `defmodule` / `defprotocol` / `defimpl` calls are skipped —
/// they are top-level definitions handled separately by the main
/// walker.
fn collect_use_and_behaviour(block: &Node, source: &str, module: &mut InheritanceNode) {
    let mut stack: Vec<Node> = vec![*block];

    while let Some(n) = stack.pop() {
        match n.kind() {
            "call" => {
                if let Some(name) = call_identifier_name(&n, source) {
                    match name.as_str() {
                        "use" => {
                            if let Some(target) = first_alias_arg(&n, source) {
                                module.bases.push(target);
                                let kinds = module.base_kinds.get_or_insert_with(Vec::new);
                                kinds.push(InheritanceKind::Extends);
                            }
                            // Don't descend into `use` arguments.
                            continue;
                        }
                        "defmodule" | "defprotocol" | "defimpl" => {
                            // Skip nested definition bodies.
                            continue;
                        }
                        _ => {}
                    }
                }
            }
            "unary_operator" => {
                // `@behaviour Mod` is an `unary_operator` whose body
                // is a `call` named `behaviour` / `behavior`.
                if is_behaviour_attribute(&n, source) {
                    if let Some(target) = behaviour_target(&n, source) {
                        module.bases.push(target);
                        let kinds = module.base_kinds.get_or_insert_with(Vec::new);
                        kinds.push(InheritanceKind::Implements);
                    }
                    continue;
                }
            }
            _ => {}
        }
        let mut cursor = n.walk();
        for child in n.children(&mut cursor) {
            stack.push(child);
        }
    }
}

/// True if this `unary_operator` is `@behaviour <Mod>`.
fn is_behaviour_attribute(node: &Node, source: &str) -> bool {
    let mut saw_at = false;
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        let txt = child.utf8_text(source.as_bytes()).unwrap_or("");
        if txt == "@" {
            saw_at = true;
            continue;
        }
        if child.kind() == "call" {
            if let Some(name) = call_identifier_name(&child, source) {
                if saw_at && (name == "behaviour" || name == "behavior") {
                    return true;
                }
            }
        }
    }
    false
}

/// Extract the module name argument from `@behaviour <Mod>`.
fn behaviour_target(node: &Node, source: &str) -> Option<String> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "call" {
            return first_alias_arg(&child, source);
        }
    }
    None
}

/// Extract a `defprotocol P do ... end` definition.
fn extract_defprotocol(
    node: &Node,
    source: &str,
    file_path: &Path,
) -> Option<InheritanceNode> {
    let name = first_alias_arg(node, source)?;
    let line = node.start_position().row as u32 + 1;
    let mut proto =
        InheritanceNode::new(name, file_path.to_path_buf(), line, Language::Elixir);
    proto.protocol = Some(true);
    proto.interface = Some(true);
    Some(proto)
}

/// Extract a `defimpl P, for: T` definition. This produces a node whose
/// name is `T` (the implementing type) with a single base `P` of kind
/// `implements`. The implementing type is intentionally surfaced as the
/// node so consumers see one edge `T -> P` per defimpl.
fn extract_defimpl(
    node: &Node,
    source: &str,
    file_path: &Path,
) -> Option<InheritanceNode> {
    let proto = first_alias_arg(node, source)?;
    let target = lookup_keyword_alias(node, source, "for")?;
    let line = node.start_position().row as u32 + 1;
    let mut impl_node =
        InheritanceNode::new(target, file_path.to_path_buf(), line, Language::Elixir);
    impl_node.bases.push(proto);
    impl_node.base_kinds = Some(vec![InheritanceKind::Implements]);
    Some(impl_node)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn parse_and_extract(source: &str) -> Vec<InheritanceNode> {
        let pool = ParserPool::new();
        extract_classes(source, &PathBuf::from("test.ex"), &pool).unwrap()
    }

    #[test]
    fn test_defprotocol_node() {
        let source = "defprotocol MyProto do\n  def encode(data)\nend\n";
        let classes = parse_and_extract(source);
        let p = classes.iter().find(|c| c.name == "MyProto").unwrap();
        assert_eq!(p.protocol, Some(true));
        assert_eq!(p.interface, Some(true));
    }

    #[test]
    fn test_defimpl_implements() {
        let source = r#"
defimpl MyProto, for: MyType do
  def encode(data), do: data
end
"#;
        let classes = parse_and_extract(source);
        let n = classes.iter().find(|c| c.name == "MyType").unwrap();
        assert!(n.bases.contains(&"MyProto".to_string()));
        assert_eq!(
            n.base_kinds.as_ref().unwrap()[0],
            InheritanceKind::Implements
        );
    }

    #[test]
    fn test_use_and_behaviour() {
        let source = r#"
defmodule MyServer do
  use GenServer
  @behaviour MyBehaviour
end
"#;
        let classes = parse_and_extract(source);
        let m = classes.iter().find(|c| c.name == "MyServer").unwrap();
        assert!(m.bases.contains(&"GenServer".to_string()));
        assert!(m.bases.contains(&"MyBehaviour".to_string()));
    }
}
