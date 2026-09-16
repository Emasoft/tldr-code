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
//! | XML/SVG  | `element`   | every `element` node — paired (`STag … ETag`) and self-closing (`EmptyElemTag`) alike, at ANY depth | the tag name; `tag#id` when an `id` attribute exists, else `tag.<first-class>` when a `class` attribute does | the whole `element` node incl. children |
//! | HTML     | `element`   | every `element` (paired or wrapping a `self_closing_tag`), `script_element`, and `style_element` | the tag name; `tag#id` when an `id` attribute exists | the whole element node incl. children |
//! | CSS      | `selector`  | every `rule_set` — top level OR nested inside an at-rule block          | the full selector text, whitespace-collapsed (`h1,\n  .card` → `h1, .card`) | the whole `rule_set` |
//! | CSS      | `at-rule`   | every BLOCK-bearing at-rule (`at_rule`, `media_statement`, `supports_statement`, `keyframes_statement`) | the at-keyword (`@media`, `@keyframes`, `@font-face`, …) | the whole statement incl. its block |
//! | LaTeX    | `section`   | every sectioning command (`part`, `chapter`, `section`, `subsection`, `subsubsection`, `paragraph`, `subparagraph` — starred variants and KOMA `\addsec`/`\addchap`/`\addpart` fold into the same node kinds) | the heading text: the braced group after the command, whitespace-collapsed; when the heading embeds commands the raw braced text is kept; with no braced heading, the command token | the whole sectioning node — the grammar nests the section's content inside it, so it spans to the next sectioning command of equal-or-higher level (or `\end{document}`/EOF) |
//! | LaTeX    | `environment` | every `\begin{env} … \end{env}` block (`generic_environment` plus the grammar's specialized `math`/`verbatim`/`listing`/`minted`/`comment`/`luacode`/`pycode`/`sageblock`/`sagesilent`/`asy`/`asydef` environment kinds); nested environments recurse | the environment name from `\begin{env}` | the whole environment node (`begin` → `end` incl. content) |
//!
//! # SVG (and other XML dialects)
//!
//! SVG needs no special casing beyond the XML walker: `.svg` maps to
//! `Language::Xml`, so `g`, `path`, `defs`, `style`, `linearGradient`, … all
//! surface as ordinary nested `element` definitions in source order — that IS
//! the requested groups/paths/elements/definitions/styles coverage — and each
//! carries a `#id` name wherever an `id` attribute exists.
//!
//! Non-elements never emit: XML prolog/doctypedecl/PIs/comments and HTML
//! doctype/comments are skipped by kind, CSS `;`-terminated statements
//! (`import_statement`, `charset_statement`, `namespace_statement`,
//! `postcss_statement`) have no block and are not regions, CSS
//! declarations are not definitions, and LaTeX preamble commands
//! (`\usepackage`, `\title`, `\label`, `\newcommand`, …), the
//! environment-DEFINING commands (`environment_definition` = `\newenvironment`,
//! `theorem_definition` = `\newtheorem`) and the brace/dollar math zones
//! (`displayed_equation`, `inline_formula` — no begin/end pair) never emit.
//!
//! # Spans
//!
//! - `byte_start`/`byte_end`: the node's `byte_range()` exactly; `byte_end` is
//!   EXCLUSIVE, so `source[byte_start..byte_end]` is the element text and
//!   starts with its first token. These are `None` for non-format code
//!   languages (the format engine, XML/HTML/CSS included, always populates
//!   them).
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
/// Returns an EMPTY vec for every non-format (code) language — the caller
/// (`extractor::extract_file_structure`) appends the result to its
/// `definitions` unconditionally.
pub fn extract_elements(language: Language, tree: &Tree, source: &str) -> Vec<DefinitionInfo> {
    let mut elements = Vec::new();
    let root = tree.root_node();

    match language {
        Language::Json => walk_json(root, source, &mut elements),
        Language::Toml => walk_toml(root, source, &mut elements),
        Language::Yaml => walk_yaml(root, source, &mut elements),
        Language::Bash => walk_bash(root, source, &mut elements),
        // Formats extension, batch E2: markup/stylesheets flow through the
        // same element engine (kinds `element` / `selector` / `at-rule`).
        Language::Xml => walk_xml(root, source, &mut elements),
        Language::Html => walk_html(root, source, &mut elements),
        Language::Css => walk_css(root, source, &mut elements),
        // LaTeX batch (2025-11): document markup joins the same engine
        // (kinds `section` / `environment`).
        Language::Latex => walk_latex(root, source, &mut elements),
        // Code languages never had elements.
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

// =============================================================================
// XML + SVG — kind "element" per element node (nested elements recurse)
// =============================================================================

/// XML (`tree_sitter_xml::LANGUAGE_XML`; serves .svg/.xsd/.xsl too): every
/// element-bearing syntax lives inside an `element` node — the grammar's
/// `element` rule is `STag content? ETag` or `EmptyElemTag` (self-closing), so
/// ONE node kind covers paired and self-closing elements alike (verified
/// against `tree-sitter-xml-0.7.0/xml/src/node-types.json`). Prolog, XML
/// declaration, doctypedecl, PIs and comments are not `element` nodes and
/// never emit; nested elements recurse in source order.
fn walk_xml(node: Node, source: &str, out: &mut Vec<DefinitionInfo>) {
    if node.kind() == "element" {
        if let Some(name) = xml_element_name(&node, source) {
            out.push(element_def("element", name, node, source));
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_xml(child, source, out);
    }
}

/// Name of an XML `element`: the tag name from the `Name` child of its start
/// tag (`STag`/`EmptyElemTag`), refined to `tag#id` when an `id` attribute
/// exists, else `tag.<first-class>` when a `class` attribute does. Attributes
/// are the `Attribute` named children of the start tag; their value is the
/// quoted `AttValue` text with its surrounding `"`/`'` stripped.
fn xml_element_name(element: &Node, source: &str) -> Option<String> {
    let mut tag = None;
    let mut id = None;
    let mut class = None;

    let mut cursor = element.walk();
    for child in element.children(&mut cursor) {
        if child.kind() != "STag" && child.kind() != "EmptyElemTag" {
            continue; // `content` / `ETag` carry no naming information
        }
        let mut tag_cursor = child.walk();
        for part in child.children(&mut tag_cursor) {
            match part.kind() {
                "Name" if tag.is_none() => tag = Some(source[part.byte_range()].to_string()),
                // NB: the xml grammar uses PascalCase kinds (Attribute,
                // AttValue) where html uses snake_case.
                "Attribute" => {
                    let (name, value) = xml_attribute(&part, source);
                    match (name.as_str(), value) {
                        ("id", v) if id.is_none() => id = v,
                        ("class", v) if class.is_none() => class = v,
                        _ => {}
                    }
                }
                _ => {}
            }
        }
    }

    let tag = tag?;
    if let Some(id) = id {
        return Some(format!("{tag}#{id}"));
    }
    if let Some(first_class) = class.as_deref().and_then(|c| c.split_whitespace().next()) {
        return Some(format!("{tag}.{first_class}"));
    }
    Some(tag)
}

/// (name, value) of an XML `Attribute` node (`Name = AttValue`); the value is
/// `None` for the (grammar-illegal but error-recovery possible) valueless
/// form. `AttValue` wraps the raw quoted text, so strip one quote pair.
fn xml_attribute(attribute: &Node, source: &str) -> (String, Option<String>) {
    let mut name = String::new();
    let mut value = None;
    let mut cursor = attribute.walk();
    for child in attribute.children(&mut cursor) {
        match child.kind() {
            "Name" if name.is_empty() => name = source[child.byte_range()].to_string(),
            "AttValue" => value = Some(unquote(&source[child.byte_range()])),
            _ => {}
        }
    }
    (name, value)
}

// =============================================================================
// HTML — kind "element" per element / script_element / style_element
// =============================================================================

/// HTML (`tree_sitter_html::LANGUAGE`; serves .xhtml too): the element-bearing
/// node kinds are `element` (paired via `start_tag … end_tag`, or wrapping a
/// lone `self_closing_tag` for void/self-closed tags), plus `script_element`
/// and `style_element` (each `start_tag raw_text? end_tag`) — verified against
/// `tree-sitter-html-0.23.2/src/node-types.json`. `doctype` and `comment` are
/// skipped by kind; nested elements recurse in source order.
fn walk_html(node: Node, source: &str, out: &mut Vec<DefinitionInfo>) {
    match node.kind() {
        "element" | "script_element" | "style_element" => {
            if let Some(name) = html_element_name(&node, source) {
                out.push(element_def("element", name, node, source));
            }
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_html(child, source, out);
    }
}

/// Name of an HTML element: the `tag_name` of its `start_tag` (or of its
/// `self_closing_tag`), suffixed `#id` when an `id` attribute is present.
/// Attribute values come from `attribute_value` — either a direct child of
/// `attribute` (unquoted syntax) or wrapped in `quoted_attribute_value` (the
/// grammar already strips the quotes).
fn html_element_name(element: &Node, source: &str) -> Option<String> {
    let mut cursor = element.walk();
    for child in element.children(&mut cursor) {
        if child.kind() == "start_tag" || child.kind() == "self_closing_tag" {
            return html_start_tag_name(&child, source);
        }
    }
    None
}

fn html_start_tag_name(tag: &Node, source: &str) -> Option<String> {
    let mut name = None;
    let mut id = None;
    let mut cursor = tag.walk();
    for child in tag.children(&mut cursor) {
        match child.kind() {
            "tag_name" if name.is_none() => name = Some(source[child.byte_range()].to_string()),
            "attribute" => {
                let (attr, value) = html_attribute(&child, source);
                if attr == "id" && id.is_none() {
                    id = value;
                }
            }
            _ => {}
        }
    }
    name.map(|tag| match id {
        Some(id) => format!("{tag}#{id}"),
        None => tag,
    })
}

/// (name, value) of an HTML `attribute` node (`attribute_name (= value)?`);
/// the value is surfaced verbatim — the grammar keeps it unquoted inside
/// `quoted_attribute_value`.
fn html_attribute(attribute: &Node, source: &str) -> (String, Option<String>) {
    let mut name = None;
    let mut value = None;
    let mut cursor = attribute.walk();
    for child in attribute.children(&mut cursor) {
        match child.kind() {
            "attribute_name" => name = Some(source[child.byte_range()].to_string()),
            "attribute_value" => value = Some(source[child.byte_range()].to_string()),
            "quoted_attribute_value" => {
                let mut inner = child.walk();
                for quoted in child.children(&mut inner) {
                    if quoted.kind() == "attribute_value" {
                        value = Some(source[quoted.byte_range()].to_string());
                    }
                }
            }
            _ => {}
        }
    }
    (name.unwrap_or_default(), value)
}

// =============================================================================
// CSS — kind "selector" per rule_set + kind "at-rule" per block at-rule
// =============================================================================

/// CSS (`tree_sitter_css::LANGUAGE`): `rule_set` nodes (prelude `selectors` +
/// `block`) emit kind `selector`; BLOCK-bearing at-rules emit kind `at-rule`.
/// tree-sitter-css 0.23.2 gives the common at-rules dedicated statement kinds
/// (`media_statement`, `supports_statement`, `keyframes_statement`) with the
/// keyword baked in as an anonymous token, while every other block at-rule
/// parses as generic `at_rule` with a named `at_keyword` child (verified
/// against `tree-sitter-css-0.23.2/src/node-types.json` + `grammar.json`).
/// `;`-terminated statements (`import_statement`, `charset_statement`,
/// `namespace_statement`, `postcss_statement`) have no block and never emit;
/// declarations are not definitions. Rules nested inside an at-rule block —
/// the media-query case, CSS nesting — recurse and emit their own selectors.
fn walk_css(node: Node, source: &str, out: &mut Vec<DefinitionInfo>) {
    match node.kind() {
        "rule_set" => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "selectors" {
                    let name = collapse_whitespace(&source[child.byte_range()]);
                    out.push(element_def("selector", name, node, source));
                    break;
                }
            }
        }
        "media_statement" | "supports_statement" | "keyframes_statement" => {
            let name = css_at_rule_name(&node, source);
            out.push(element_def("at-rule", name, node, source));
        }
        "at_rule" => {
            // Generic at-rules may also terminate with `;` (no block); only
            // block-bearing ones are structural at-rule regions.
            let mut has_block = false;
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "block" {
                    has_block = true;
                    break;
                }
            }
            if has_block {
                let name = css_at_rule_name(&node, source);
                out.push(element_def("at-rule", name, node, source));
            }
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_css(child, source, out);
    }
}

/// Name of a CSS at-rule: the `at_keyword` child when the grammar exposes one
/// (`at_rule`, `keyframes_statement`), else the statement's first token — for
/// `media_statement`/`supports_statement` the keyword is an anonymous literal
/// at the node's start (`@media`/`@supports`).
fn css_at_rule_name(rule: &Node, source: &str) -> String {
    let mut cursor = rule.walk();
    for child in rule.children(&mut cursor) {
        if child.kind() == "at_keyword" {
            return source[child.byte_range()].to_string();
        }
    }
    source[rule.byte_range()]
        .split(|c: char| c.is_whitespace() || c == '{')
        .next()
        .unwrap_or("")
        .to_string()
}

/// CSS selector text: collapse every whitespace run to one space and trim, so
/// `h1,\n  .card` reads as `h1, .card`.
fn collapse_whitespace(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

// =============================================================================
// LaTeX — kind "section" per sectioning command + kind "environment" per
// \begin{env} … \end{env} block
// =============================================================================

/// Node kinds of the LaTeX grammar that wrap a `\begin{env} … \end{env}`
/// block (verified against `codebook-tree-sitter-latex-0.6.1/src/node-types.json`
/// — the republished latex-lsp grammar: all of them carry required
/// `begin`/`end` fields pointing at `begin`/`end` nodes). `generic_environment` covers every non-special-cased name
/// (document, itemize, figure, table, center, …); the grammar gives the
/// common special-content environments dedicated kinds (`math_environment`
/// for equation/align/gather/multline/…, `verbatim_environment`,
/// `listing_environment`, `minted_environment`, `comment_environment`,
/// `luacode_environment`, `pycode_environment`, `sageblock_environment`,
/// `sagesilent_environment`, `asy_environment`, `asydef_environment`).
/// `environment_definition` (\newenvironment) and `theorem_definition`
/// (\newtheorem) are NOT in this list — they define environments in the
/// preamble, they do not open one.
const LATEX_ENVIRONMENT_KINDS: &[&str] = &[
    "generic_environment",
    "math_environment",
    "verbatim_environment",
    "listing_environment",
    "minted_environment",
    "comment_environment",
    "luacode_environment",
    "pycode_environment",
    "sageblock_environment",
    "sagesilent_environment",
    "asy_environment",
    "asydef_environment",
];

/// LaTeX (`codebook_tree_sitter_latex::LANGUAGE`; serves .tex/.sty/.cls).
/// Two element kinds, both shape-given by the grammar (verified against
/// `codebook-tree-sitter-latex-0.6.1/src/node-types.json`, the republished
/// latex-lsp/tree-sitter-latex grammar):
///
/// - `section`: the sectioning commands are DEDICATED named nodes — `part`,
///   `chapter`, `section`, `subsection`, `subsubsection`, `paragraph`,
///   `subparagraph` (one kind per level; starred variants `\section*` and the
///   KOMA spellings `\addsec`/`\addchap`/`\addpart` fold into the same node
///   kind). The grammar nests the section's CONTENT inside the sectioning
///   node: a `section` node's allowed children include
///   `subsection`/`subsubsection`/`paragraph`/`subparagraph` (its own level
///   and below, never a sibling `section`), `chapter` includes `section` but
///   not a sibling `chapter`, and so on down the hierarchy. A section node's
///   byte range therefore ALREADY spans everything up to the next sectioning
///   command of equal-or-higher level (or `\end{document}`/EOF) — the
///   content-spanning region LaTeX semantics call for, delivered by the tree
///   itself; no sibling-boundary math is needed (and none could be as
///   faithful: the hierarchy is the grammar's, not reconstructible from
///   sibling pointers alone).
/// - `environment`: every begin/end-bearing environment node spans its whole
///   `\begin{…} … \end{…}` range and nests (a `generic_environment`'s
///   children include every environment kind), so nested environments
///   recurse and each gets its own definition in source order.
///
/// Preamble commands and math zones never emit (see the module doc).
fn walk_latex(node: Node, source: &str, out: &mut Vec<DefinitionInfo>) {
    let kind = node.kind();
    if matches!(
        kind,
        "part"
            | "chapter"
            | "section"
            | "subsection"
            | "subsubsection"
            | "paragraph"
            | "subparagraph"
    ) {
        out.push(element_def(
            "section",
            latex_section_name(&node, source),
            node,
            source,
        ));
    } else if LATEX_ENVIRONMENT_KINDS.contains(&kind) {
        if let Some(name) = latex_environment_name(&node, source) {
            out.push(element_def("environment", name, node, source));
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_latex(child, source, out);
    }
}

/// Heading text of a sectioning node: the source text of its braced `text`
/// group (`curly_group` field `text`), whitespace-collapsed. If the heading
/// embeds nested commands (`\section{The \emph{Fast} Method}`) the raw
/// braced text is kept verbatim — word-collecting would silently drop the
/// emphasised words. With no usable braced heading (degenerate `\section`
/// with no argument) the command token itself names the element so the
/// structure report still shows a navigable row.
fn latex_section_name(section: &Node, source: &str) -> String {
    if let Some(text) = section.child_by_field_name("text") {
        // `curly_group` spans `{ … }`; the heading is the braced interior.
        let raw = &source[text.byte_range()];
        let inner = raw
            .strip_prefix('{')
            .and_then(|s| s.strip_suffix('}'))
            .unwrap_or(raw);
        if !inner.contains('\\') {
            let plain = collapse_whitespace(inner);
            if !plain.is_empty() {
                return plain;
            }
        }
        let trimmed = inner.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    section
        .child_by_field_name("command")
        .map(|c| source[c.byte_range()].to_string())
        .unwrap_or_default()
}

/// Environment name: the `begin` child's `name` field — a `curly_group_text`
/// wrapping the bare environment word (`\begin{itemize}` → `itemize`). The
/// grammar marks `name` required on `begin`, so the `None` path is reserved
/// for malformed trees; an unusable name suppresses the element (matching
/// the XML walker's behaviour for a tagless element).
fn latex_environment_name(environment: &Node, source: &str) -> Option<String> {
    let name = environment
        .child_by_field_name("begin")?
        .child_by_field_name("name")?;
    let raw = &source[name.byte_range()];
    let inner = raw
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .unwrap_or(raw);
    let name = collapse_whitespace(inner);
    if name.is_empty() {
        None
    } else {
        Some(name)
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
    fn markup_formats_emit_elements_with_id_and_class_naming() {
        // HTML: paired elements, a script_element, a style_element, an id
        // name, and a void (self-closing) element.
        let src = "<html><head><title>Page</title><style>a{}</style></head>\
                   <body><script src=\"app.js\"></script><br/></body></html>";
        let tree = parse(src, Language::Html).unwrap();
        let elements = extract_elements(Language::Html, &tree, src);
        let names: Vec<&str> = elements.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["html", "head", "title", "style", "body", "script", "br"]
        );
        for e in &elements {
            assert_eq!(e.kind, "element");
        }

        // XML: id-naming and class-naming on nested elements.
        let src = "<?xml version=\"1.0\"?><root id=\"r\"><child/></root>";
        let tree = parse(src, Language::Xml).unwrap();
        let elements = extract_elements(Language::Xml, &tree, src);
        let names: Vec<&str> = elements.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["root#r", "child"]);

        // CSS: selectors and at-rules, with the media-query inner rule
        // surfacing as its own nested selector.
        let src = "body { color: red; }\n@media (min-width: 1px) { b { color: blue } }\n";
        let tree = parse(src, Language::Css).unwrap();
        let elements = extract_elements(Language::Css, &tree, src);
        let kinds: Vec<&str> = elements.iter().map(|e| e.kind.as_str()).collect();
        let names: Vec<&str> = elements.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(kinds, vec!["selector", "at-rule", "selector"]);
        assert_eq!(names, vec!["body", "@media", "b"]);
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
