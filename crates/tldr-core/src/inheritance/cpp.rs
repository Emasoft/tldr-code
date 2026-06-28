//! C/C++ class extraction for inheritance analysis.
//!
//! Extracts `class` / `struct` definitions from C/C++ source code using
//! tree-sitter and emits an inheritance edge for each `base_class_clause`
//! entry. Handles:
//!
//! - Public / protected / private inheritance (the access keyword is
//!   stripped — we only emit the base type name).
//! - Multiple inheritance (`class D : public A, public B { ... };`).
//! - `virtual` inheritance (modifier stripped).
//! - Generic / templated bases (e.g. `class D : public Vec<T>`) — we keep
//!   the bare type identifier so the resolver can match across files.
//!
//! Module added by real-repo-fixes-v1 (P9.BUG-R4): `tldr inheritance` was
//! returning zero edges for cpp despite eight obvious public-inheritance
//! relations in `tinyxml2.h`. Tree-sitter-cpp's `class_specifier` carries
//! a `base_class_clause` child with one or more `base_class_clause` entries,
//! and we walk every `class_specifier` / `struct_specifier` in the tree —
//! mirroring `extract_cpp_classes` in `crates/tldr-core/src/ast/extractor.rs`.

use std::path::Path;

use tree_sitter::Node;

use crate::ast::parser::ParserPool;
use crate::types::{InheritanceNode, Language};
use crate::TldrResult;

/// Extract class / struct definitions from C++ source code, including
/// inheritance edges (`base_class_clause`).
pub fn extract_classes(
    source: &str,
    file_path: &Path,
    parser_pool: &ParserPool,
) -> TldrResult<Vec<InheritanceNode>> {
    let tree = parser_pool.parse(source, Language::Cpp)?;
    let mut classes = Vec::new();

    let root = tree.root_node();
    visit_node(&root, source, file_path, &mut classes);

    Ok(classes)
}

/// Same extractor reused for plain C — `struct Foo { ... }` typically has
/// no inheritance, but the walker still surfaces the type as a node so
/// downstream pattern detection can run uniformly.
pub fn extract_classes_c(
    source: &str,
    file_path: &Path,
    parser_pool: &ParserPool,
) -> TldrResult<Vec<InheritanceNode>> {
    let tree = parser_pool.parse(source, Language::C)?;
    let mut classes = Vec::new();

    let root = tree.root_node();
    visit_node_with_lang(&root, source, file_path, &mut classes, Language::C);

    Ok(classes)
}

fn visit_node(node: &Node, source: &str, file_path: &Path, classes: &mut Vec<InheritanceNode>) {
    visit_node_with_lang(node, source, file_path, classes, Language::Cpp);
}

fn visit_node_with_lang(
    node: &Node,
    source: &str,
    file_path: &Path,
    classes: &mut Vec<InheritanceNode>,
    lang: Language,
) {
    match node.kind() {
        "class_specifier" => {
            if let Some(class) = extract_class_specifier(node, source, file_path, lang, false) {
                classes.push(class);
            }
        }
        "struct_specifier" => {
            // A `struct_specifier` is only a *definition* when it carries a
            // body (`field_declaration_list`). A bodyless `struct_specifier`
            // is a type *reference* — `sizeof(struct sdshdr8)`,
            // `struct Foo *p;`, a `struct Foo` parameter, or a forward
            // declaration `struct Foo;` — and must not enter the inventory.
            // Counting them doubled the inheritance inventory on real C code
            // (PW5 bug9: redis sds.c emitted 5 phantom `sdshdrN` nodes from
            // the `sizeof(struct sdshdrN)` switch — 10 vs 5). structs can
            // also inherit in C++ (default access = public), and an
            // inheriting struct always has a body, so this guard never drops
            // a real base edge. Mirrors the VAL-001 body check in
            // `ast/extractor.rs`.
            if node.child_by_field_name("body").is_some() {
                if let Some(class) =
                    extract_class_specifier(node, source, file_path, lang, true)
                {
                    classes.push(class);
                }
            }
        }
        // Tree-sitter-cpp misparses `class MACRO Name : public Base { ... };`
        // as a `function_definition` (or `declaration`) whose `type` field
        // is a `class_specifier` for `class MACRO`, declarator=identifier
        // (the real class name), followed by an `ERROR` node holding
        // `: public Base` and a `compound_statement` body.
        //
        // Recover the real class name and the single-base inheritance edge
        // from this misparse — without this, every macro-prefixed cpp class
        // (the dominant style in tinyxml2.h, Boost, Folly, etc.) collapses
        // to the macro name and inheritance edges vanish entirely.
        // real-repo-fixes-v1 (P9.BUG-R4).
        "function_definition" | "declaration" => {
            if let Some(class) =
                extract_macro_prefixed_class(node, source, file_path, lang)
            {
                classes.push(class);
                // review-followup-v1 (Concern 2): when the misparse path
                // recovered the real class, do NOT recurse into the
                // `function_definition` / `declaration` children — the
                // `type` child is a `class_specifier` whose `name` is the
                // macro token (e.g. `TINYXML2_LIB`). Recursing emits that
                // macro name as a phantom `InheritanceNode` with zero
                // bases. The node is fully accounted for by the
                // `extract_macro_prefixed_class` result, so skip the walk.
                return;
            }
        }
        _ => {}
    }

    // Recurse into children — class_specifier nodes may live inside
    // namespaces, preprocessor branches, or even (in real-world parses)
    // misclassified function_definition / ERROR wrappers. Mirrors the
    // walk in `tldr extract`.
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        visit_node_with_lang(&child, source, file_path, classes, lang);
    }
}

/// Recover a `class MACRO Name : public Base { ... }` declaration that
/// tree-sitter-cpp has misparsed as `function_definition` (single base) or
/// `declaration` (multiple bases). Returns `None` for non-misparses (real
/// function definitions / variable declarations).
fn extract_macro_prefixed_class(
    node: &Node,
    source: &str,
    file_path: &Path,
    lang: Language,
) -> Option<InheritanceNode> {
    // Must have type field that is itself a class_specifier (for `class MACRO`).
    let type_node = node.child_by_field_name("type")?;
    if type_node.kind() != "class_specifier" && type_node.kind() != "struct_specifier" {
        return None;
    }

    // Real class name comes from the declarator field of the misparse —
    // a bare `identifier` for `function_definition`, or for `declaration`
    // it's a direct `identifier` child (with init_declarator handling for
    // multi-base which we treat as same single-class with the first base).
    let declarator = node.child_by_field_name("declarator")?;
    let class_name: String = match declarator.kind() {
        "identifier" => declarator
            .utf8_text(source.as_bytes())
            .ok()?
            .trim()
            .to_string(),
        _ => return None,
    };
    if class_name.is_empty() {
        return None;
    }

    let line = node.start_position().row as u32 + 1;
    let mut class_node =
        InheritanceNode::new(class_name, file_path.to_path_buf(), line, lang);

    // Look for a sibling ERROR node that holds the base clause `: public Foo`.
    // The ERROR node lives as a direct child of the misparsed
    // function_definition / declaration, not of the type's class_specifier.
    class_node.bases = extract_macro_error_base_clause(node, source);

    Some(class_node)
}

/// Pull base class names out of the `ERROR` siblings of a misparsed
/// macro-prefixed class declaration.
///
/// The ERROR node typically contains tokens `:`, optional `public` /
/// `protected` / `private` / `virtual`, then the base type identifier(s).
/// Any number of identifiers may be present (single inheritance is the
/// common case; multiple inheritance with macros is not always recoverable
/// because tree-sitter scrambles the parse further).
fn extract_macro_error_base_clause(node: &Node, source: &str) -> Vec<String> {
    let mut bases = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() != "ERROR" {
            continue;
        }
        let mut sub_cursor = child.walk();
        for sub in child.children(&mut sub_cursor) {
            // Skip access modifiers and punctuation; collect identifiers.
            let kind = sub.kind();
            if kind == "identifier" || kind == "type_identifier" {
                if let Ok(text) = sub.utf8_text(source.as_bytes()) {
                    let text = text.trim();
                    if !text.is_empty()
                        && !matches!(
                            text,
                            "public" | "protected" | "private" | "virtual"
                        )
                    {
                        bases.push(text.to_string());
                    }
                }
            } else if kind == "qualified_identifier" || kind == "template_type" {
                if let Some(name) = extract_base_name(&sub, source) {
                    bases.push(name);
                }
            }
        }
    }
    bases
}

/// Extract a `class_specifier` (or `struct_specifier`) node.
///
/// Tree-sitter-cpp grammar:
/// * `name` field — `type_identifier` for the class name
/// * `body` field — `field_declaration_list` with members
/// * a child of kind `base_class_clause` holds `:` then one or more
///   base specifiers separated by commas. Each base specifier consists
///   of optional access modifiers (`public`/`protected`/`private`/`virtual`)
///   followed by a `type_identifier`, `qualified_identifier`, or
///   `template_type` for the base.
///
/// Forward declarations (`class Foo;`) have no body and no base clause.
/// We still emit them as nodes (zero bases) so they appear in the
/// inheritance graph as roots/leaves consistently with other languages.
fn extract_class_specifier(
    node: &Node,
    source: &str,
    file_path: &Path,
    lang: Language,
    is_struct: bool,
) -> Option<InheritanceNode> {
    let name_node = node.child_by_field_name("name")?;
    let name = name_node.utf8_text(source.as_bytes()).ok()?.to_string();

    if name.is_empty() {
        return None;
    }

    let line = node.start_position().row as u32 + 1;
    let mut class_node = InheritanceNode::new(name, file_path.to_path_buf(), line, lang);

    class_node.bases = extract_base_class_clause(node, source);

    // For pattern detection structs and classes are equivalent; we don't
    // tag them separately because `InheritanceNode` doesn't carry a kind
    // discriminator. The `is_struct` flag is reserved for future use.
    let _ = is_struct;

    Some(class_node)
}

/// Walk a `class_specifier`'s children for a `base_class_clause` and
/// extract every base type name.
fn extract_base_class_clause(node: &Node, source: &str) -> Vec<String> {
    let mut bases = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "base_class_clause" {
            let mut sub_cursor = child.walk();
            for sub in child.children(&mut sub_cursor) {
                if let Some(name) = extract_base_name(&sub, source) {
                    if !name.is_empty() {
                        bases.push(name);
                    }
                }
            }
        }
    }
    bases
}

/// Pull a base type name out of a child of `base_class_clause`.
///
/// Children may be:
/// * literal tokens (`:`, `,`, `public`, `protected`, `private`, `virtual`) —
///   skip these.
/// * `type_identifier` — direct match (`public Base` → `Base`).
/// * `qualified_identifier` — keep last segment for cross-file resolution
///   (the `resolve` module already understands fully-qualified names but
///   the pattern detectors compare on the simple name).
/// * `template_type` — strip template arguments, keep the bare identifier.
fn extract_base_name(node: &Node, source: &str) -> Option<String> {
    match node.kind() {
        "type_identifier" => node
            .utf8_text(source.as_bytes())
            .ok()
            .map(|s| s.trim().to_string()),
        "qualified_identifier" => {
            // Find the right-most type_identifier child (the simple name).
            let mut cursor = node.walk();
            let mut last_simple: Option<String> = None;
            for child in node.children(&mut cursor) {
                if child.kind() == "type_identifier" {
                    if let Ok(text) = child.utf8_text(source.as_bytes()) {
                        last_simple = Some(text.trim().to_string());
                    }
                } else if child.kind() == "qualified_identifier"
                    || child.kind() == "template_type"
                {
                    if let Some(nested) = extract_base_name(&child, source) {
                        last_simple = Some(nested);
                    }
                }
            }
            last_simple
        }
        "template_type" => {
            // `Foo<Bar>` → keep `Foo` (simple name) for cross-file matching.
            if let Some(name) = node.child_by_field_name("name") {
                return name
                    .utf8_text(source.as_bytes())
                    .ok()
                    .map(|s| s.trim().to_string());
            }
            // Fallback: first type_identifier child.
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "type_identifier" {
                    return child
                        .utf8_text(source.as_bytes())
                        .ok()
                        .map(|s| s.trim().to_string());
                }
            }
            None
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_and_extract(source: &str) -> Vec<InheritanceNode> {
        let pool = ParserPool::new();
        extract_classes(source, Path::new("test.cpp"), &pool).unwrap()
    }

    fn parse_and_extract_c(source: &str) -> Vec<InheritanceNode> {
        let pool = ParserPool::new();
        extract_classes_c(source, Path::new("test.c"), &pool).unwrap()
    }

    #[test]
    fn test_simple_class() {
        let source = "class Foo { public: int x; };";
        let nodes = parse_and_extract(source);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "Foo");
        assert!(nodes[0].bases.is_empty());
    }

    #[test]
    fn test_single_inheritance() {
        let source = "class Base {}; class Derived : public Base {};";
        let nodes = parse_and_extract(source);
        let derived = nodes.iter().find(|n| n.name == "Derived").unwrap();
        assert_eq!(derived.bases, vec!["Base"]);
    }

    #[test]
    fn test_multiple_inheritance() {
        let source =
            "class A {}; class B {}; class C : public A, public B {};";
        let nodes = parse_and_extract(source);
        let c = nodes.iter().find(|n| n.name == "C").unwrap();
        assert_eq!(c.bases, vec!["A", "B"]);
    }

    #[test]
    fn test_virtual_inheritance() {
        let source = "class Base {}; class Derived : virtual public Base {};";
        let nodes = parse_and_extract(source);
        let derived = nodes.iter().find(|n| n.name == "Derived").unwrap();
        assert_eq!(derived.bases, vec!["Base"]);
    }

    #[test]
    fn test_namespace_class() {
        let source = "namespace foo { class Base {}; class D : public Base {}; }";
        let nodes = parse_and_extract(source);
        let d = nodes.iter().find(|n| n.name == "D").unwrap();
        assert_eq!(d.bases, vec!["Base"]);
    }

    #[test]
    fn test_template_base() {
        let source = "template<typename T> class Vec {}; class IntVec : public Vec<int> {};";
        let nodes = parse_and_extract(source);
        let iv = nodes.iter().find(|n| n.name == "IntVec").unwrap();
        assert_eq!(iv.bases, vec!["Vec"]);
    }


    #[test]
    fn test_macro_prefixed_class_inheritance() {
        // Real-world cpp headers use `class TINYXML2_LIB Name : public Base`
        // where the macro confuses tree-sitter into a function_definition
        // wrapper. Verify our walker recovers the inheritance edge.
        let source =
            "class MACRO XMLText : public XMLNode {\npublic:\n    int x;\n};";
        let nodes = parse_and_extract(source);
        let xt = nodes.iter().find(|n| n.name == "XMLText");
        assert!(
            xt.is_some(),
            "Expected to recover XMLText class from macro-prefixed declaration; got {:?}",
            nodes.iter().map(|n| &n.name).collect::<Vec<_>>()
        );
        assert_eq!(xt.unwrap().bases, vec!["XMLNode"]);
    }

    // PW5 bug9: `sizeof(struct X)` and other bodyless `struct_specifier`
    // type-references were being counted as struct *definitions*, doubling
    // the inheritance inventory on real C code (redis sds.c emitted 5
    // phantom `sdshdrN` nodes from the `sizeof(struct sdshdrN)` switch).
    // A struct is only a definition when it carries a body
    // (`field_declaration_list`).

    #[test]
    fn test_c_sizeof_struct_not_counted_as_definition() {
        // Mirrors redis sds.c/sds.h: one real struct definition, plus a
        // function that references the type via `sizeof(struct sdshdr8)`.
        let source = "\
struct sdshdr8 { unsigned char flags; char buf[]; };
static int hdr_size(void) {
    return sizeof(struct sdshdr8);
}";
        let nodes = parse_and_extract_c(source);
        let count = nodes.iter().filter(|n| n.name == "sdshdr8").count();
        assert_eq!(
            count, 1,
            "real `struct sdshdr8` def must be counted exactly once \
             (sizeof type-ref must NOT add a phantom); got {:?}",
            nodes.iter().map(|n| &n.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_cpp_sizeof_struct_not_counted_as_definition() {
        // Same symptom in C++: a bodyless `struct_specifier` inside
        // `sizeof(...)` must not register as a definition.
        let source = "\
struct Header { int len; };
int header_size() {
    return sizeof(struct Header);
}";
        let nodes = parse_and_extract(source);
        let count = nodes.iter().filter(|n| n.name == "Header").count();
        assert_eq!(
            count, 1,
            "real `struct Header` def must be counted exactly once; got {:?}",
            nodes.iter().map(|n| &n.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_c_multiple_sizeof_refs_single_definition() {
        // The exact shape that produced the 10-vs-5 doubling: N real defs
        // plus N `sizeof(struct X)` references must yield exactly N nodes.
        let source = "\
struct sdshdr5  { unsigned char flags; char buf[]; };
struct sdshdr8  { unsigned char flags; char buf[]; };
struct sdshdr16 { unsigned char flags; char buf[]; };
static int hdr_size(char type) {
    switch (type) {
        case 5:  return sizeof(struct sdshdr5);
        case 8:  return sizeof(struct sdshdr8);
        case 16: return sizeof(struct sdshdr16);
    }
    return 0;
}";
        let nodes = parse_and_extract_c(source);
        assert_eq!(
            nodes.len(),
            3,
            "expected exactly 3 struct definitions (no phantom type-refs); got {:?}",
            nodes.iter().map(|n| &n.name).collect::<Vec<_>>()
        );
        for name in ["sdshdr5", "sdshdr8", "sdshdr16"] {
            assert_eq!(
                nodes.iter().filter(|n| n.name == name).count(),
                1,
                "{name} must appear exactly once",
            );
        }
    }

    #[test]
    fn test_c_struct_pointer_and_var_refs_not_counted() {
        // Other bodyless `struct_specifier` references (pointer field,
        // local variable, function parameter) are likewise type-refs, not
        // definitions.
        let source = "\
struct Node { int v; };
struct Node *make(struct Node *parent) {
    struct Node *n;
    return n;
}";
        let nodes = parse_and_extract_c(source);
        let count = nodes.iter().filter(|n| n.name == "Node").count();
        assert_eq!(
            count, 1,
            "pointer/param/local references to `struct Node` must not add \
             phantom definitions; got {:?}",
            nodes.iter().map(|n| &n.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_c_forward_declaration_not_counted() {
        // A bodyless forward declaration `struct Foo;` is not a definition.
        let source = "struct Foo; struct Foo { int x; };";
        let nodes = parse_and_extract_c(source);
        assert_eq!(
            nodes.iter().filter(|n| n.name == "Foo").count(),
            1,
            "forward decl must not double-count `Foo`; got {:?}",
            nodes.iter().map(|n| &n.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_cpp_inheriting_struct_with_body_still_counted() {
        // Guard must NOT drop real struct definitions, including inheriting
        // structs in C++ (which always have a body).
        let source = "struct Base {}; struct Derived : public Base {};";
        let nodes = parse_and_extract(source);
        let derived = nodes
            .iter()
            .find(|n| n.name == "Derived")
            .expect("inheriting struct Derived must still be counted");
        assert_eq!(derived.bases, vec!["Base"]);
        assert!(
            nodes.iter().any(|n| n.name == "Base"),
            "real `struct Base` definition must still be counted",
        );
    }
}
