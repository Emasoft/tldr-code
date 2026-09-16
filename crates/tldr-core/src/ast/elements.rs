//! Element extraction for data/config formats (element-extraction-v1, Phase E).
//!
//! Formats have no functions/classes/methods, so `extract_definitions` returns
//! EMPTY for them — a `tldr structure config.json` report was previously all
//! headings and no rows. This module walks the same tree-sitter tree and emits
//! **element-level definitions** through the existing `DefinitionInfo` channel
//! (`kind` is a free `String`, so no schema break): structure, the daemon, and
//! every other `extract_file_structure` consumer see them automatically.
//!
//! # Kind taxonomy (the authoritative table for this module)
//!
//! | Language | Kind        | What it is                                                            | Name                          | Region                                             |
//! |----------|-------------|-----------------------------------------------------------------------|-------------------------------|----------------------------------------------------|
//! | JSON     | `key`       | every object property (`pair`), at ANY nesting depth                   | the key, unquoted              | the `pair` node incl. its value; array items are NOT definitions, but a property whose value is an array/object still emits its key once |
//! | TOML     | `section`   | `[table.path]` / `[[table.path]]` headers                              | the dotted path, keys unquoted | the whole `table`/`table_array_element` block       |
//! | TOML     | `key`       | every key/value `pair` — top-level, inside a section, or in an inline table | the key (dotted keys joined with `.`), unquoted | the `pair` node |
//! | YAML     | `document`  | each `---`-delimited document of the stream                            | `document-N` (N = 1-indexed source-order position) | the `document` node incl. its `---` marker |
//! | YAML     | `key`       | top-level mapping keys of each document                                | the key, unquoted              | the `block_mapping_pair` (key + whole value subtree) |
//! | Bash     | `function`  | `function_definition` (`name() {}` and `function name {}`)             | the function name              | the whole `function_definition` node |
//!
//! XML/HTML/CSS (and any code language) return EMPTY here — their element
//! kinds (`element`, `selector`, `at-rule`) land in a later batch.
//!
//! # Spans
//!
//! - `byte_start`/`byte_end`: the node's `byte_range()` exactly; `byte_end` is
//!   EXCLUSIVE, so `source[byte_start..byte_end]` is the element text and
//!   starts with its first token. These are `None` for code languages.
//! - `line_start`: first line (1-indexed) containing node bytes.
//! - `line_end`: last line (1-indexed) containing node bytes — the trailing
//!   `end_position().row + 1` convention would spill onto a phantom line when
//!   a node's last byte is a newline (e.g. a YAML document or TOML table that
//!   runs to EOF), so that one newline is attributed to the element's last
//!   real line instead.
//! - `definition_line`: `None` — formats carry no trivia/declaration split.
//! - `signature`: a one-line summary (the element's first source line), so
//!   text-mode and JSON consumers see what the region opens with.
//!
//! # Determinism
//!
//! Every walker is a pre-order depth-first traversal emitting in source order.
//! No HashMap/HashSet iteration participates in output ordering.

use tree_sitter::{Node, Tree};

use crate::types::{DefinitionInfo, Language};

/// Extract format elements as `DefinitionInfo` entries.
///
/// Returns an EMPTY vec for every non-format language (including XML/HTML/CSS
/// until their batch) — the caller (`extractor::extract_file_structure`) appends
/// the result to its `definitions` unconditionally.
pub fn extract_elements(language: Language, tree: &Tree, source: &str) -> Vec<DefinitionInfo> {
    let mut elements = Vec::new();
    let root = tree.root_node();

    match language {
        Language::Json => walk_json(root, source, &mut elements),
        Language::Toml => walk_toml(root, source, &mut elements),
        Language::Yaml => walk_yaml(root, source, &mut elements),
        Language::Bash => walk_bash(root, source, &mut elements),
        // Formats extension: XML/HTML/CSS keep the empty baseline until their
        // element batch; code languages never had elements.
        _ => {}
    }

    elements
}

// =============================================================================
// Shared helpers
// =============================================================================

/// Build an element definition from a node: line span from the node's rows
/// (trailing-newline trimmed, see the module doc), byte span from the node's
/// byte range, signature = the element's first source line.
fn element_def(kind: &str, name: String, node: Node, source: &str) -> DefinitionInfo {
    let bytes = source.as_bytes();
    let line_start = node.start_position().row as u32 + 1;
    // A node whose last byte is a newline would put `end_position().row + 1`
    // on the phantom line after it (worse: a YAML document or TOML table at
    // EOF lands one line past the file). That newline belongs to the element's
    // last real line, so stop there.
    let line_end =
        if node.end_byte() > node.start_byte() && bytes.get(node.end_byte() - 1) == Some(&b'\n') {
            node.end_position().row as u32
        } else {
            node.end_position().row as u32 + 1
        };

    let signature = source[node.byte_range()]
        .lines()
        .next()
        .unwrap_or("")
        .trim()
        .to_string();

    DefinitionInfo {
        name,
        kind: kind.to_string(),
        line_start,
        line_end,
        definition_line: None,
        byte_start: Some(node.start_byte() as u64),
        byte_end: Some(node.end_byte() as u64),
        signature,
    }
}

/// Strip one pair of surrounding single/double quotes (JSON/YAML/TOML keys).
fn unquote(text: &str) -> String {
    let bytes = text.as_bytes();
    if bytes.len() >= 2
        && (bytes[0] == b'"' || bytes[0] == b'\'')
        && bytes[bytes.len() - 1] == bytes[0]
    {
        text[1..text.len() - 1].to_string()
    } else {
        text.to_string()
    }
}

// =============================================================================
// JSON — kind "key" per object property (nested keys recurse)
// =============================================================================

fn walk_json(node: Node, source: &str, out: &mut Vec<DefinitionInfo>) {
    if node.kind() == "pair" {
        // `pair` fields: key (string), value (_value). A pair IS the region
        // (key + value, whatever the value is — object, array, scalar), so a
        // property with an array/object value emits its key exactly once.
        if let Some(key) = node.child_by_field_name("key") {
            out.push(element_def(
                "key",
                json_key_name(&key, source),
                node,
                source,
            ));
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_json(child, source, out);
    }
}

/// JSON key text: the grammar nests the raw key inside `string` →
/// `string_content`; prefer the content child, fall back to unquoting.
fn json_key_name(key: &Node, source: &str) -> String {
    let mut cursor = key.walk();
    for child in key.children(&mut cursor) {
        if child.kind() == "string_content" {
            return source[child.byte_range()].to_string();
        }
    }
    unquote(&source[key.byte_range()])
}

// =============================================================================
// TOML — kind "section" per table header + kind "key" per pair
// =============================================================================

fn walk_toml(node: Node, source: &str, out: &mut Vec<DefinitionInfo>) {
    match node.kind() {
        "table" | "table_array_element" => {
            // Header = the key-part children before the first `pair`.
            let path = toml_header_path(&node, source);
            if !path.is_empty() {
                out.push(element_def("section", path, node, source));
            }
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                walk_toml(child, source, out);
            }
        }
        "pair" => {
            if let Some(name) = toml_pair_name(&node, source) {
                out.push(element_def("key", name, node, source));
            }
            // Recurse so inline-table pairs (`x = { a = 1 }`) surface too.
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                walk_toml(child, source, out);
            }
        }
        _ => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                walk_toml(child, source, out);
            }
        }
    }
}

/// Dotted path of a `[header]`: the key-part named children before the first
/// `pair` (bare_key / quoted_key / dotted_key), joined with `.`.
fn toml_header_path(table: &Node, source: &str) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut cursor = table.walk();
    for child in table.children(&mut cursor) {
        if child.kind() == "pair" {
            break;
        }
        match child.kind() {
            "bare_key" | "quoted_key" => parts.push(unquote(&source[child.byte_range()])),
            "dotted_key" => parts.extend(toml_key_parts(&child, source)),
            _ => {}
        }
    }
    parts.join(".")
}

/// Key text of a `pair`'s leading key part (bare / quoted / dotted).
fn toml_pair_name(pair: &Node, source: &str) -> Option<String> {
    let mut cursor = pair.walk();
    for child in pair.children(&mut cursor) {
        match child.kind() {
            "bare_key" | "quoted_key" => {
                return Some(unquote(&source[child.byte_range()]));
            }
            "dotted_key" => {
                return Some(toml_key_parts(&child, source).join("."));
            }
            _ => {}
        }
    }
    None
}

/// Flatten a `dotted_key` (which may nest dotted_keys) into its parts in
/// source order, unquoting each.
fn toml_key_parts(dotted: &Node, source: &str) -> Vec<String> {
    let mut parts = Vec::new();
    collect_key_parts(*dotted, source, &mut parts);
    parts
}

fn collect_key_parts(node: Node, source: &str, parts: &mut Vec<String>) {
    match node.kind() {
        "bare_key" | "quoted_key" => parts.push(unquote(&source[node.byte_range()])),
        "dotted_key" => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                collect_key_parts(child, source, parts);
            }
        }
        _ => {}
    }
}

// =============================================================================
// YAML — kind "document" per --- document + top-level kind "key"
// =============================================================================

fn walk_yaml(node: Node, source: &str, out: &mut Vec<DefinitionInfo>) {
    // The root is a `stream` of `document` nodes (multi-doc files repeat the
    // node; the `---` marker is INSIDE its document's span).
    if node.kind() == "stream" {
        let mut cursor = node.walk();
        for (idx, child) in node.children(&mut cursor).enumerate() {
            if child.kind() == "document" {
                out.push(element_def(
                    "document",
                    format!("document-{}", idx + 1),
                    child,
                    source,
                ));
                emit_yaml_top_level_keys(&child, source, out);
            }
        }
    }
}

/// Top-level mapping keys of one YAML document: block mappings surface their
/// `block_mapping_pair`s; flow mappings (`{a: 1}`) their `flow_pair`s. The
/// region is the pair node — key plus the whole value subtree.
fn emit_yaml_top_level_keys(document: &Node, source: &str, out: &mut Vec<DefinitionInfo>) {
    let mut cursor = document.walk();
    for child in document.children(&mut cursor) {
        if child.kind() == "block_node" || child.kind() == "flow_node" {
            let mut inner = child.walk();
            for content in child.children(&mut inner) {
                match content.kind() {
                    "block_mapping" => {
                        let mut pairs = content.walk();
                        for pair in content.children(&mut pairs) {
                            if pair.kind() == "block_mapping_pair" {
                                if let Some(name) = yaml_pair_name(&pair, source) {
                                    out.push(element_def("key", name, pair, source));
                                }
                            }
                        }
                    }
                    "flow_mapping" => {
                        let mut pairs = content.walk();
                        for pair in content.children(&mut pairs) {
                            if pair.kind() == "flow_pair" {
                                if let Some(name) = yaml_pair_name(&pair, source) {
                                    out.push(element_def("key", name, pair, source));
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

/// YAML key text: `key` field → flow/block node → scalar child; unquote
/// single/double-quoted scalars, keep plain scalars verbatim.
fn yaml_pair_name(pair: &Node, source: &str) -> Option<String> {
    let key = pair.child_by_field_name("key")?;
    let mut cursor = key.walk();
    for child in key.children(&mut cursor) {
        if child.kind() == "plain_scalar"
            || child.kind() == "single_quote_scalar"
            || child.kind() == "double_quote_scalar"
        {
            return Some(unquote(&source[child.byte_range()]));
        }
        // flow_node/block_node wrappers: descend one level.
        let mut inner = child.walk();
        for scalar in child.children(&mut inner) {
            if scalar.kind() == "plain_scalar"
                || scalar.kind() == "single_quote_scalar"
                || scalar.kind() == "double_quote_scalar"
            {
                return Some(unquote(&source[scalar.byte_range()]));
            }
        }
    }
    None
}

// =============================================================================
// Bash — kind "function" per function_definition
// =============================================================================

fn walk_bash(node: Node, source: &str, out: &mut Vec<DefinitionInfo>) {
    if node.kind() == "function_definition" {
        // Both `build() { … }` and `function build { … }` put the name in the
        // `name` field (a `word` node) — bash is format-tier but has real,
        // region-bearing functions, so it flows through the element engine.
        if let Some(name_node) = node.child_by_field_name("name") {
            let name = source[name_node.byte_range()].to_string();
            out.push(element_def("function", name, node, source));
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_bash(child, source, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::parser::parse;

    #[test]
    fn non_format_languages_return_empty() {
        let tree = parse("def foo(): pass", Language::Python).unwrap();
        assert!(extract_elements(Language::Python, &tree, "def foo(): pass").is_empty());
        let tree = parse("fn foo() {}", Language::Rust).unwrap();
        assert!(extract_elements(Language::Rust, &tree, "fn foo() {}").is_empty());
    }

    #[test]
    fn html_css_xml_return_empty_until_their_batch() {
        for (src, lang) in [
            ("<html><body></body></html>", Language::Html),
            ("body { color: red; }", Language::Css),
            ("<?xml version=\"1.0\"?><root/>", Language::Xml),
        ] {
            let tree = parse(src, lang).unwrap();
            assert!(
                extract_elements(lang, &tree, src).is_empty(),
                "{lang:?} must keep the empty baseline until its element batch"
            );
        }
    }

    #[test]
    fn json_array_items_are_not_definitions() {
        let src = r#"{"items": [1, {"a": 2}]}"#;
        let tree = parse(src, Language::Json).unwrap();
        let elements = extract_elements(Language::Json, &tree, src);
        let names: Vec<&str> = elements.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["items", "a"], "array scalars are not elements");
        // The outer key spans the whole array; the nested key only its pair.
        assert_eq!(elements[0].line_start, 1);
        assert_eq!(elements[0].line_end, 1);
        // The nested pair's slice is exactly its `"a": 2` region (the object's
        // closing brace belongs to the object, not the pair).
        let nested = &elements[1];
        let slice = &src[nested.byte_start.unwrap() as usize..nested.byte_end.unwrap() as usize];
        assert_eq!(slice, r#""a": 2"#);
    }

    #[test]
    fn yaml_documents_are_numbered_in_source_order() {
        let src = "a: 1\n---\nb: 2\n";
        let tree = parse(src, Language::Yaml).unwrap();
        let elements = extract_elements(Language::Yaml, &tree, src);
        let named: Vec<(String, String)> = elements
            .iter()
            .map(|e| (e.kind.clone(), e.name.clone()))
            .collect();
        assert_eq!(
            named,
            vec![
                ("document".to_string(), "document-1".to_string()),
                ("key".to_string(), "a".to_string()),
                ("document".to_string(), "document-2".to_string()),
                ("key".to_string(), "b".to_string()),
            ]
        );
    }

    #[test]
    fn byte_spans_slice_back_to_the_element() {
        let src = "x = { a = 1, b = 2 }\n[table]\ny = 3\n";
        let tree = parse(src, Language::Toml).unwrap();
        let elements = extract_elements(Language::Toml, &tree, src);
        for e in &elements {
            let (start, end) = match (e.byte_start, e.byte_end) {
                (Some(s), Some(en)) => (s as usize, en as usize),
                other => panic!("element {:?} must carry byte spans, got {other:?}", e.name),
            };
            assert!(end > start, "element {:?} must be non-empty", e.name);
            let slice = &src[start..end];
            assert!(
                slice.starts_with(e.name.as_str()) || slice.starts_with('['),
                "slice for {:?} must start with the element's first token: {slice:?}",
                e.name
            );
        }
        let kinds: Vec<&str> = elements.iter().map(|e| e.kind.as_str()).collect();
        assert_eq!(kinds, vec!["key", "key", "key", "section", "key"]);
    }

    #[test]
    fn elements_carry_byte_spans_and_code_languages_do_not() {
        let json_src = r#"{"k": 1}"#;
        let tree = parse(json_src, Language::Json).unwrap();
        let elements = extract_elements(Language::Json, &tree, json_src);
        assert_eq!(elements.len(), 1);
        assert!(elements[0].byte_start.is_some() && elements[0].byte_end.is_some());
        assert!(elements[0].definition_line.is_none());

        let tree = parse("fn foo() {}", Language::Rust).unwrap();
        // (code-language path returns empty — byte spans stay None everywhere
        // until the code-language batch populates them)
        assert!(extract_elements(Language::Rust, &tree, "fn foo() {}").is_empty());
    }
}
