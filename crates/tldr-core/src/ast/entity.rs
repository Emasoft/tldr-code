//! Canonical entity span + signature resolver (RC2-META Stage 1).
//!
//! The three signature producers — `structure` (`extractor::collect_definitions`
//! → `method_infos`), `interface` (`patterns::interface::extract_function_signature`),
//! and `extract` (`extract.rs` detailed arms) — historically each sliced the
//! WHOLE declaration node and mangled signatures differently:
//!
//! ```text
//! structure : "m(): void {} }"   (first source line of the whole node — body leaks in)
//! interface : "(): : void"       (params field + return-type field whose text already
//!                                 carries its own leading `: `, producing a double colon)
//! ```
//!
//! The root fix (validated against rust-analyzer `ptr` vs `name_ptr`, and LSP
//! `range` vs `selectionRange`) is to render a signature from the declaration
//! HEADER span — the name + parameter list + return type — and to STOP at the
//! body block. [`signature_from_header`] is that shared, AST-driven resolver.
//!
//! This module is intentionally minimal for Stage 1. It GROWS in Stage 2 (a
//! shared `classify_node` discriminator); do NOT pre-build the kind enum here.

use tree_sitter::Node;

/// A byte/row span pinned from a tree-sitter node.
///
/// Mirrors the LSP `range` (whole node) vs `selectionRange` (name) split: the
/// `signature` producers want the HEADER span, not the whole-node span, so the
/// body block never leaks into the rendered signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    /// Inclusive start byte offset into the source.
    pub start_byte: usize,
    /// Exclusive end byte offset into the source.
    pub end_byte: usize,
    /// 0-indexed start row.
    pub start_row: usize,
    /// 0-indexed end row.
    pub end_row: usize,
}

impl Span {
    /// Pin a [`Span`] from a tree-sitter node (the whole-node `range`).
    pub fn from_node(node: Node) -> Self {
        Span {
            start_byte: node.start_byte(),
            end_byte: node.end_byte(),
            start_row: node.start_position().row,
            end_row: node.end_position().row,
        }
    }
}

/// The byte offset where the declaration BODY block begins, if any.
///
/// Used to bound the header span so an inline body (`{ ... }` on the same line
/// as the signature, e.g. `m(): void {}`) is excluded. AST-driven: prefers the
/// grammar's explicit `body` field, then falls back to the well-known block
/// node kinds across the supported grammars. NO source-text/regex heuristics.
fn body_start_byte(node: Node) -> Option<usize> {
    // The explicit `body` field covers the large majority of function/method
    // declaration nodes across TS/JS, Rust, Go, Java, C#, Kotlin, Scala,
    // Python, C/C++, PHP, Swift.
    if let Some(b) = node.child_by_field_name("body") {
        return Some(b.start_byte());
    }
    // Fallback: scan for the first child that is a recognised body block.
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "statement_block"      // TS/JS
            | "block"              // Rust / Python / Lua / Kotlin
            | "function_body"      // Swift
            | "compound_statement" // C / C++
            | "do_block"           // Elixir
            | "field_declaration_list" => {
                return Some(child.start_byte());
            }
            _ => {}
        }
    }
    None
}

/// Byte offset of the first child that is NOT a leading comment / attribute /
/// decorator — i.e. the start of the real declaration header.
///
/// Mirrors the skip-list used by `extractor::extract_def_signature` so the two
/// resolvers agree on where the header begins (doc comments, Rust `#[...]`,
/// Python `@decorator`, etc. are skipped).
fn header_start_byte(node: Node) -> usize {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "line_comment" | "block_comment" | "comment" | "attribute_item"
            | "attribute" | "decorator" | "decorator_list" => continue,
            _ => return child.start_byte(),
        }
    }
    node.start_byte()
}

/// Render a single-line signature from the declaration HEADER span.
///
/// The header span is `[first-meaningful-child .. body-block-start)`, clipped to
/// the first source line so a multi-line header collapses to its declaration
/// line exactly as the legacy first-line extractor did (zero churn for the
/// common multi-line case). The ONLY behavioural change versus the legacy
/// whole-node first-line slice is that an inline body block (`{ ... }` on the
/// signature line) is excluded — which is precisely the mangling this fixes:
///
/// ```text
/// "m(): void {} }"  ->  "m(): void"
/// ```
///
/// AST-driven: spans are pinned via tree-sitter node fields/children, never via
/// regex or string trimming of arbitrary source.
pub fn signature_from_header(node: Node, source: &str) -> String {
    let header_start = header_start_byte(node);

    // Clip to the first source line of the header (legacy parity for multi-line
    // declarations whose body opens on a later line).
    let rest = source.get(header_start..).unwrap_or("");
    let first_line_end = header_start + rest.find('\n').unwrap_or(rest.len());

    // Stop at the body block if it opens within the first line.
    let end = match body_start_byte(node) {
        Some(b) if b > header_start => first_line_end.min(b),
        _ => first_line_end,
    };

    let sig = source.get(header_start..end).unwrap_or("").trim().to_string();
    if !sig.is_empty() {
        return sig;
    }

    // Fallback: whole-node first line (matches the legacy last-resort behaviour).
    source
        .get(node.start_byte()..)
        .and_then(|s| s.lines().next())
        .unwrap_or("")
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::parser::parse;
    use crate::types::Language;

    /// Find the first descendant node of the given kind (depth-first).
    fn find_kind<'a>(node: Node<'a>, kind: &str) -> Option<Node<'a>> {
        if node.kind() == kind {
            return Some(node);
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if let Some(found) = find_kind(child, kind) {
                return Some(found);
            }
        }
        None
    }

    #[test]
    fn ts_method_signature_excludes_inline_body() {
        let source = "class Qux { m(): void {} }\n";
        let tree = parse(source, Language::TypeScript).unwrap();
        let method = find_kind(tree.root_node(), "method_definition")
            .expect("method_definition node");
        // Whole-node text is the mangled "m(): void {}"; the header span must
        // drop the body block entirely.
        assert_eq!(signature_from_header(method, source), "m(): void");
    }

    #[test]
    fn ts_function_signature_excludes_inline_body() {
        let source = "function add(a: number, b: number): number { return a + b; }\n";
        let tree = parse(source, Language::TypeScript).unwrap();
        let func = find_kind(tree.root_node(), "function_declaration")
            .expect("function_declaration node");
        assert_eq!(
            signature_from_header(func, source),
            "function add(a: number, b: number): number"
        );
    }

    #[test]
    fn ts_constructor_signature_excludes_inline_body() {
        let source = "class P { constructor(x: number) { this.x = x; } }\n";
        let tree = parse(source, Language::TypeScript).unwrap();
        let ctor = find_kind(tree.root_node(), "method_definition")
            .expect("constructor method_definition node");
        assert_eq!(signature_from_header(ctor, source), "constructor(x: number)");
    }

    #[test]
    fn bodyless_method_signature_is_unchanged() {
        // An interface method signature has NO body block; the header span is
        // the whole single-line node (trailing `;` preserved — legacy parity).
        let source = "interface Foo {\n  b(): void;\n}\n";
        let tree = parse(source, Language::TypeScript).unwrap();
        let sig_node = find_kind(tree.root_node(), "method_signature")
            .expect("method_signature node");
        assert_eq!(signature_from_header(sig_node, source), "b(): void;");
    }

    #[test]
    fn multiline_header_collapses_to_declaration_line() {
        // The opening brace is on a LATER line, so the header span is just the
        // first declaration line — identical to the legacy first-line slice.
        let source = "function foo(\n  a: number\n): void {\n  return;\n}\n";
        let tree = parse(source, Language::TypeScript).unwrap();
        let func = find_kind(tree.root_node(), "function_declaration")
            .expect("function_declaration node");
        assert_eq!(signature_from_header(func, source), "function foo(");
    }
}
