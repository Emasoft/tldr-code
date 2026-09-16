//! element-extraction-v1 — the executable spec for format element extraction.
//!
//! CONTRACT UNDER TEST (element-extraction-v1, Phase E step 1 of 4):
//!
//! Data/config formats have no functions/classes/methods, so
//! `extract_definitions` returns EMPTY for them. `ast::elements` walks the
//! same tree and emits **element-level definitions** through the existing
//! `DefinitionInfo` channel, appended inside `extract_file_structure` so every
//! consumer (structure/daemon/JSON) receives them automatically:
//!
//! - JSON  → `key` per object property, at any nesting depth (a property whose
//!   value is an array/object still emits its key once; array items are not
//!   definitions)
//! - TOML  → `section` per `[table.path]`/`[[table.path]]` header (name =
//!   dotted path) + `key` per key/value pair
//! - YAML  → `document` per `---` document (name = `document-N`) + `key` per
//!   top-level mapping key of each document (region = key + whole value
//!   subtree)
//! - Bash  → `function` per `function_definition` (bash is format-tier but
//!   has real functions)
//! - XML/SVG → `element` per `element` node (paired + self-closing), named
//!   `tag`, `tag#id` (id attribute wins) or `tag.<first-class>` (class attr);
//!   SVG needs no special casing — g/path/defs/style surface as ordinary
//!   nested elements
//! - HTML  → `element` per `element`/`script_element`/`style_element` node,
//!   named `tag` or `tag#id`; doctype/comments skipped
//! - CSS   → `selector` per `rule_set` (whitespace-collapsed selector text,
//!   incl. rules nested inside at-rules) + `at-rule` per block at-rule
//!   (named after its at-keyword)
//!
//! Every element pins:
//! 1. EXACT `kind` / `name` / `line_start` / `line_end` (1-indexed), and
//! 2. byte spans present & consistent: `byte_start < byte_end` and
//!    `source[byte_start..byte_end]` starts with the element's first token.
//!
//! Code languages keep `byte_start`/`byte_end` = `None` for now (populating
//! them is a later batch); the format engine — markup formats included —
//! always populates them.

use std::fs;

use tempfile::TempDir;
use tldr_core::types::DefinitionInfo;
use tldr_core::{get_code_structure, Language};

// =============================================================================
// Helpers
// =============================================================================

/// Write `content` to `<tempdir>/<filename>` and run the PUBLIC structure
/// extraction with an EXPLICIT language — the same path `tldr structure`
/// takes (extractor.rs single-file mode honors the caller language).
fn extract_elements(filename: &str, content: &str, language: Language) -> Vec<DefinitionInfo> {
    let dir =
        TempDir::new().unwrap_or_else(|e| panic!("element-extraction-v1: tempdir failed: {e}"));
    let path = dir.path().join(filename);
    fs::write(&path, content).unwrap_or_else(|e| {
        panic!("element-extraction-v1: failed to write fixture {filename}: {e}")
    });

    let structure = get_code_structure(&path, language, 0, None)
        .unwrap_or_else(|e| panic!("element-extraction-v1: extraction failed for {filename}: {e}"));

    assert_eq!(
        structure.files.len(),
        1,
        "element-extraction-v1 [{filename}]: expected exactly one FileStructure"
    );
    structure.files[0].definitions.clone()
}

/// Find an element by kind + name, dumping the full list on miss so a RED run
/// reads as a report.
fn find_element<'a>(
    defs: &'a [DefinitionInfo],
    file: &str,
    kind: &str,
    name: &str,
) -> &'a DefinitionInfo {
    defs.iter()
        .find(|d| d.kind == kind && d.name == name)
        .unwrap_or_else(|| {
            panic!(
                "element-extraction-v1 [{file}]: element {kind}:`{name}` not found.\n\
                 Extracted definitions ({})=\n{defs:#?}",
                defs.len()
            )
        })
}

/// EXACT span assertion: the failure message is the actual-vs-expected row.
fn assert_span(def: &DefinitionInfo, file: &str, label: &str, start: u32, end: u32) {
    assert!(
        def.line_start == start && def.line_end == end,
        "element-extraction-v1 [{file}] {label}: expected line span {start}..{end}, \
         got {}..{} (kind=`{}`, name=`{}`)",
        def.line_start,
        def.line_end,
        def.kind,
        def.name
    );
}

/// Byte spans must be present, ordered (start < end — elements are never
/// empty), and the slice must open with the element's first token.
fn assert_byte_slice(def: &DefinitionInfo, source: &str, file: &str, first_token: &str) {
    let (start, end) = match (def.byte_start, def.byte_end) {
        (Some(s), Some(e)) => (s as usize, e as usize),
        other => panic!(
            "element-extraction-v1 [{file}] {}:`{}` must carry byte spans, got {other:?}",
            def.kind, def.name
        ),
    };
    assert!(
        end > start,
        "element-extraction-v1 [{file}] {}:`{}`: byte_end ({end}) must exceed byte_start ({start})",
        def.kind,
        def.name
    );
    let slice = &source[start..end];
    assert!(
        slice.starts_with(first_token),
        "element-extraction-v1 [{file}] {}:`{}`: source[byte_start..byte_end] must start with \
         the element's first token {first_token:?}, got {slice:?}",
        def.kind,
        def.name
    );
    // And the slice must stay inside the source bounds (trivially true given
    // the slice succeeded, but pinned so a future u64/i64/usize refactor
    // cannot silently wrap).
    assert!(end <= source.len());
}

/// Every element: no attribution line (formats have no trivia/decl split),
/// line_end >= line_start, and definition_line is never set.
fn assert_element_invariants(defs: &[DefinitionInfo], file: &str) {
    for d in defs {
        assert!(
            d.line_end >= d.line_start,
            "element-extraction-v1 [{file}]: {}:`{}` has line_end ({}) < line_start ({})",
            d.kind,
            d.name,
            d.line_end,
            d.line_start
        );
        assert!(
            d.definition_line.is_none(),
            "element-extraction-v1 [{file}]: {}:`{}` must not set definition_line",
            d.kind,
            d.name
        );
        assert!(
            d.byte_start.is_some() && d.byte_end.is_some(),
            "element-extraction-v1 [{file}]: {}:`{}` must carry byte spans",
            d.kind,
            d.name
        );
    }
}

// =============================================================================
// JSON — nested object: outer key, inner key, array-valued key
// =============================================================================

const JSON_FIXTURE: &str = r#"{
  "name": "demo",
  "nested": {
    "inner": true
  },
  "items": [1, 2, 3]
}
"#;

#[test]
fn json_nested_object_elements() {
    let defs = extract_elements("pinned.json", JSON_FIXTURE, Language::Json);
    assert_element_invariants(&defs, "pinned.json");

    // EXACT element set, in source order: array items are NOT definitions,
    // and each key is emitted exactly once regardless of its value's shape.
    let kinds: Vec<&str> = defs.iter().map(|d| d.kind.as_str()).collect();
    assert_eq!(
        kinds,
        vec!["key", "key", "key", "key"],
        "element-extraction-v1 [pinned.json]: expected exactly 4 keys in source order"
    );

    let name = find_element(&defs, "pinned.json", "key", "name");
    assert_span(name, "pinned.json", "key:name", 2, 2);
    assert_byte_slice(name, JSON_FIXTURE, "pinned.json", "\"name\"");

    // Outer key spans its whole object value (key line through closing brace).
    let nested = find_element(&defs, "pinned.json", "key", "nested");
    assert_span(nested, "pinned.json", "key:nested", 3, 5);
    assert_byte_slice(nested, JSON_FIXTURE, "pinned.json", "\"nested\"");

    // A nested key is its own definition.
    let inner = find_element(&defs, "pinned.json", "key", "inner");
    assert_span(inner, "pinned.json", "key:inner", 4, 4);
    assert_byte_slice(inner, JSON_FIXTURE, "pinned.json", "\"inner\"");

    // Array-valued key: emitted once, spanning only its own line (the array
    // stays on it) — the array's scalar items are not elements.
    let items = find_element(&defs, "pinned.json", "key", "items");
    assert_span(items, "pinned.json", "key:items", 6, 6);
    assert_byte_slice(items, JSON_FIXTURE, "pinned.json", "\"items\"");
}

// =============================================================================
// TOML — two sections + keys, incl. a dotted table header
// =============================================================================

const TOML_FIXTURE: &str = "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n\n[build.target.x86]\nfeature = \"sse\"\n\n[tool.rust]\nedition = \"2021\"\n";

#[test]
fn toml_sections_and_keys() {
    let defs = extract_elements("pinned.toml", TOML_FIXTURE, Language::Toml);
    assert_element_invariants(&defs, "pinned.toml");

    // EXACT source-order sequence: section headers interleave with their keys.
    let sequence: Vec<(String, String)> = defs
        .iter()
        .map(|d| (d.kind.clone(), d.name.clone()))
        .collect();
    let expected: Vec<(String, String)> = [
        ("section", "package"),
        ("key", "name"),
        ("key", "version"),
        ("section", "build.target.x86"),
        ("key", "feature"),
        ("section", "tool.rust"),
        ("key", "edition"),
    ]
    .iter()
    .map(|(k, n)| (k.to_string(), n.to_string()))
    .collect();
    assert_eq!(
        sequence, expected,
        "element-extraction-v1 [pinned.toml]: expected exact section/key sequence"
    );

    // A section spans its whole block (header through the last line before the
    // next header); a dotted header keeps its dotted name, unquoted.
    let package = find_element(&defs, "pinned.toml", "section", "package");
    assert_span(package, "pinned.toml", "section:package", 1, 4);
    assert_byte_slice(package, TOML_FIXTURE, "pinned.toml", "[package]");

    let dotted = find_element(&defs, "pinned.toml", "section", "build.target.x86");
    assert_span(dotted, "pinned.toml", "section:build.target.x86", 5, 7);
    assert_byte_slice(dotted, TOML_FIXTURE, "pinned.toml", "[build.target.x86]");

    let tool = find_element(&defs, "pinned.toml", "section", "tool.rust");
    assert_span(tool, "pinned.toml", "section:tool.rust", 8, 9);
    assert_byte_slice(tool, TOML_FIXTURE, "pinned.toml", "[tool.rust]");

    let name = find_element(&defs, "pinned.toml", "key", "name");
    assert_span(name, "pinned.toml", "key:name", 2, 2);
    assert_byte_slice(name, TOML_FIXTURE, "pinned.toml", "name");

    let feature = find_element(&defs, "pinned.toml", "key", "feature");
    assert_span(feature, "pinned.toml", "key:feature", 6, 6);
    assert_byte_slice(feature, TOML_FIXTURE, "pinned.toml", "feature");

    let edition = find_element(&defs, "pinned.toml", "key", "edition");
    assert_span(edition, "pinned.toml", "key:edition", 9, 9);
    assert_byte_slice(edition, TOML_FIXTURE, "pinned.toml", "edition");
}

// =============================================================================
// YAML — two documents, top-level keys per document
// =============================================================================

const YAML_FIXTURE: &str = "name: demo\nitems:\n  - one\n  - two\n---\nkind: config\nmode: fast\n";

#[test]
fn yaml_two_documents_with_top_level_keys() {
    let defs = extract_elements("pinned.yaml", YAML_FIXTURE, Language::Yaml);
    assert_element_invariants(&defs, "pinned.yaml");

    // EXACT source-order sequence: documents first, then their top-level keys.
    let sequence: Vec<(String, String)> = defs
        .iter()
        .map(|d| (d.kind.clone(), d.name.clone()))
        .collect();
    let expected: Vec<(String, String)> = [
        ("document", "document-1"),
        ("key", "name"),
        ("key", "items"),
        ("document", "document-2"),
        ("key", "kind"),
        ("key", "mode"),
    ]
    .iter()
    .map(|(k, n)| (k.to_string(), n.to_string()))
    .collect();
    assert_eq!(
        sequence, expected,
        "element-extraction-v1 [pinned.yaml]: expected exact document/key sequence"
    );

    // document-1 has no `---` marker; it spans its content lines.
    let doc1 = find_element(&defs, "pinned.yaml", "document", "document-1");
    assert_span(doc1, "pinned.yaml", "document-1", 1, 4);
    assert_byte_slice(doc1, YAML_FIXTURE, "pinned.yaml", "name");

    // document-2 starts AT its `---` marker.
    let doc2 = find_element(&defs, "pinned.yaml", "document", "document-2");
    assert_span(doc2, "pinned.yaml", "document-2", 5, 7);
    assert_byte_slice(doc2, YAML_FIXTURE, "pinned.yaml", "---");

    // Top-level keys only — the sequence items under `items` are not elements,
    // and the key's region covers the whole value subtree.
    let name = find_element(&defs, "pinned.yaml", "key", "name");
    assert_span(name, "pinned.yaml", "key:name", 1, 1);
    assert_byte_slice(name, YAML_FIXTURE, "pinned.yaml", "name");

    let items = find_element(&defs, "pinned.yaml", "key", "items");
    assert_span(items, "pinned.yaml", "key:items", 2, 4);
    assert_byte_slice(items, YAML_FIXTURE, "pinned.yaml", "items");

    let kind = find_element(&defs, "pinned.yaml", "key", "kind");
    assert_span(kind, "pinned.yaml", "key:kind", 6, 6);
    assert_byte_slice(kind, YAML_FIXTURE, "pinned.yaml", "kind");

    let mode = find_element(&defs, "pinned.yaml", "key", "mode");
    assert_span(mode, "pinned.yaml", "key:mode", 7, 7);
    assert_byte_slice(mode, YAML_FIXTURE, "pinned.yaml", "mode");
}

// =============================================================================
// Bash — two functions (both `name() {}` and `function name {}` forms)
// =============================================================================

const BASH_FIXTURE: &str = "#!/usr/bin/env bash\n\nbuild() {\n  echo building\n}\n\nfunction deploy {\n  echo deploying\n}\n";

#[test]
fn bash_functions() {
    let defs = extract_elements("deploy.sh", BASH_FIXTURE, Language::Bash);
    assert_element_invariants(&defs, "deploy.sh");

    let kinds: Vec<&str> = defs.iter().map(|d| d.kind.as_str()).collect();
    assert_eq!(
        kinds,
        vec!["function", "function"],
        "element-extraction-v1 [deploy.sh]: expected exactly 2 functions"
    );

    let build = find_element(&defs, "deploy.sh", "function", "build");
    assert_span(build, "deploy.sh", "function:build", 3, 5);
    assert_byte_slice(build, BASH_FIXTURE, "deploy.sh", "build");

    // `function deploy { … }` — the keyword form — names the function, not
    // the keyword.
    let deploy = find_element(&defs, "deploy.sh", "function", "deploy");
    assert_span(deploy, "deploy.sh", "function:deploy", 7, 9);
    assert_byte_slice(deploy, BASH_FIXTURE, "deploy.sh", "function");
}

// =============================================================================
// XML — nested elements, id/class naming, self-closing children
// =============================================================================

const XML_FIXTURE: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
                           <catalog id=\"cat1\">\n\
                           \x20 <book id=\"bk101\">\n\
                           \x20   <title>Language</title>\n\
                           \x20 </book>\n\
                           \x20 <book class=\"ref manual\">\n\
                           \x20   <isbn/>\n\
                           \x20 </book>\n\
                           </catalog>\n";

#[test]
fn xml_nested_elements_with_id_and_class_naming() {
    let defs = extract_elements("pinned.xml", XML_FIXTURE, Language::Xml);
    assert_element_invariants(&defs, "pinned.xml");

    // EXACT source-order element set: the prolog never emits, nested children
    // are their own definitions, id wins over class, class keeps its FIRST
    // value, and self-closing elements are elements too.
    let sequence: Vec<(String, String)> = defs
        .iter()
        .map(|d| (d.kind.clone(), d.name.clone()))
        .collect();
    let expected: Vec<(String, String)> = [
        ("element", "catalog#cat1"),
        ("element", "book#bk101"),
        ("element", "title"),
        ("element", "book.ref"),
        ("element", "isbn"),
    ]
    .iter()
    .map(|(k, n)| (k.to_string(), n.to_string()))
    .collect();
    assert_eq!(
        sequence, expected,
        "element-extraction-v1 [pinned.xml]: expected exact element sequence"
    );

    // The catalog element spans its whole subtree.
    let catalog = find_element(&defs, "pinned.xml", "element", "catalog#cat1");
    assert_span(catalog, "pinned.xml", "element:catalog#cat1", 2, 9);
    assert_byte_slice(catalog, XML_FIXTURE, "pinned.xml", "<catalog");

    let title = find_element(&defs, "pinned.xml", "element", "title");
    assert_span(title, "pinned.xml", "element:title", 4, 4);
    assert_byte_slice(title, XML_FIXTURE, "pinned.xml", "<title>");

    let isbn = find_element(&defs, "pinned.xml", "element", "isbn");
    assert_span(isbn, "pinned.xml", "element:isbn", 7, 7);
    assert_byte_slice(isbn, XML_FIXTURE, "pinned.xml", "<isbn/>");
}

// =============================================================================
// SVG — plain XML: g/path/defs/style surface as ordinary nested elements
// =============================================================================

const SVG_FIXTURE: &str = "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 10 10\">\n\
                           \x20 <defs>\n\
                           \x20   <linearGradient id=\"grad\"/>\n\
                           \x20 </defs>\n\
                           \x20 <g id=\"grp\" class=\"shapes\">\n\
                           \x20   <path d=\"M0 0\"/>\n\
                           \x20   <circle cx=\"5\" cy=\"5\" r=\"4\"/>\n\
                           \x20 </g>\n\
                           \x20 <style>.a { fill: red; }</style>\n\
                           </svg>\n";

#[test]
fn svg_groups_paths_defs_and_style_are_nested_elements() {
    let defs = extract_elements("icon.svg", SVG_FIXTURE, Language::Xml);
    assert_element_invariants(&defs, "icon.svg");

    // No SVG special-casing: every nested element is an ordinary `element`
    // definition in source order, `#id`-named wherever an id exists.
    let sequence: Vec<(String, String)> = defs
        .iter()
        .map(|d| (d.kind.clone(), d.name.clone()))
        .collect();
    let expected: Vec<(String, String)> = [
        ("element", "svg"),
        ("element", "defs"),
        ("element", "linearGradient#grad"),
        ("element", "g#grp"),
        ("element", "path"),
        ("element", "circle"),
        ("element", "style"),
    ]
    .iter()
    .map(|(k, n)| (k.to_string(), n.to_string()))
    .collect();
    assert_eq!(
        sequence, expected,
        "element-extraction-v1 [icon.svg]: expected exact nested element sequence"
    );

    let g = find_element(&defs, "icon.svg", "element", "g#grp");
    assert_span(g, "icon.svg", "element:g#grp", 5, 8);
    assert_byte_slice(g, SVG_FIXTURE, "icon.svg", "<g");

    let style = find_element(&defs, "icon.svg", "element", "style");
    assert_span(style, "icon.svg", "element:style", 9, 9);
    assert_byte_slice(style, SVG_FIXTURE, "icon.svg", "<style>");
}

// =============================================================================
// HTML — element tree incl. script/style elements and id naming
// =============================================================================

const HTML_FIXTURE: &str = "<!DOCTYPE html>\n\
                            <html lang=\"en\">\n\
                            \x20 <head>\n\
                            \x20   <title>Page</title>\n\
                            \x20   <style>body { color: red; }</style>\n\
                            \x20 </head>\n\
                            \x20 <body id=\"main\">\n\
                            \x20   <script src=\"app.js\"></script>\n\
                            \x20   <p>Hello</p>\n\
                            \x20   <br/>\n\
                            \x20 </body>\n\
                            </html>\n";

#[test]
fn html_element_tree_with_script_style_and_id_naming() {
    let defs = extract_elements("pinned.html", HTML_FIXTURE, Language::Html);
    assert_element_invariants(&defs, "pinned.html");

    // Doctype is skipped; script_element/style_element are `element` kinds;
    // the void `<br/>` is an element; `body` carries its `#id` name.
    let sequence: Vec<(String, String)> = defs
        .iter()
        .map(|d| (d.kind.clone(), d.name.clone()))
        .collect();
    let expected: Vec<(String, String)> = [
        ("element", "html"),
        ("element", "head"),
        ("element", "title"),
        ("element", "style"),
        ("element", "body#main"),
        ("element", "script"),
        ("element", "p"),
        ("element", "br"),
    ]
    .iter()
    .map(|(k, n)| (k.to_string(), n.to_string()))
    .collect();
    assert_eq!(
        sequence, expected,
        "element-extraction-v1 [pinned.html]: expected exact element sequence"
    );

    let body = find_element(&defs, "pinned.html", "element", "body#main");
    assert_span(body, "pinned.html", "element:body#main", 7, 11);
    assert_byte_slice(body, HTML_FIXTURE, "pinned.html", "<body");

    let script = find_element(&defs, "pinned.html", "element", "script");
    assert_span(script, "pinned.html", "element:script", 8, 8);
    assert_byte_slice(script, HTML_FIXTURE, "pinned.html", "<script");

    let br = find_element(&defs, "pinned.html", "element", "br");
    assert_span(br, "pinned.html", "element:br", 10, 10);
    assert_byte_slice(br, HTML_FIXTURE, "pinned.html", "<br/>");
}

// =============================================================================
// CSS — selectors (incl. comma lists) + at-rules with nested rule recursion
// =============================================================================

const CSS_FIXTURE: &str = "/* base */\n\
                           body {\n\
                           \x20 color: red;\n\
                           }\n\
                           \n\
                           h1, h2 .card {\n\
                           \x20 margin: 0;\n\
                           }\n\
                           \n\
                           @media (min-width: 40em) {\n\
                           \x20 .inner {\n\
                           \x20   color: blue;\n\
                           \x20 }\n\
                           }\n\
                           \n\
                           @keyframes spin {\n\
                           \x20 from { opacity: 0; }\n\
                           }\n";

#[test]
fn css_selectors_at_rules_and_at_rule_recursion() {
    let defs = extract_elements("pinned.css", CSS_FIXTURE, Language::Css);
    assert_element_invariants(&defs, "pinned.css");

    // EXACT sequence: two top-level rules (comma selector whitespace-
    // collapsed), the @media at-rule, ITS inner rule as a nested selector,
    // and the @keyframes at-rule (its `from` is a keyframe block, not a
    // rule_set). Declarations never emit.
    let sequence: Vec<(String, String)> = defs
        .iter()
        .map(|d| (d.kind.clone(), d.name.clone()))
        .collect();
    let expected: Vec<(String, String)> = [
        ("selector", "body"),
        ("selector", "h1, h2 .card"),
        ("at-rule", "@media"),
        ("selector", ".inner"),
        ("at-rule", "@keyframes"),
    ]
    .iter()
    .map(|(k, n)| (k.to_string(), n.to_string()))
    .collect();
    assert_eq!(
        sequence, expected,
        "element-extraction-v1 [pinned.css]: expected exact selector/at-rule sequence"
    );

    let body = find_element(&defs, "pinned.css", "selector", "body");
    assert_span(body, "pinned.css", "selector:body", 2, 4);
    assert_byte_slice(body, CSS_FIXTURE, "pinned.css", "body");

    let comma = find_element(&defs, "pinned.css", "selector", "h1, h2 .card");
    assert_span(comma, "pinned.css", "selector:h1, h2 .card", 6, 8);
    assert_byte_slice(comma, CSS_FIXTURE, "pinned.css", "h1");

    let media = find_element(&defs, "pinned.css", "at-rule", "@media");
    assert_span(media, "pinned.css", "at-rule:@media", 10, 14);
    assert_byte_slice(media, CSS_FIXTURE, "pinned.css", "@media");

    let inner = find_element(&defs, "pinned.css", "selector", ".inner");
    assert_span(inner, "pinned.css", "selector:.inner", 11, 13);
    assert_byte_slice(inner, CSS_FIXTURE, "pinned.css", ".inner");

    let keyframes = find_element(&defs, "pinned.css", "at-rule", "@keyframes");
    assert_span(keyframes, "pinned.css", "at-rule:@keyframes", 16, 18);
    assert_byte_slice(keyframes, CSS_FIXTURE, "pinned.css", "@keyframes");
}

// =============================================================================
// Cross-format: the JSON shape consumers see is the plain definitions array
// =============================================================================

#[test]
fn elements_flow_through_the_definitions_array_of_every_format() {
    for (filename, content, language, min_elements) in [
        ("pinned.json", JSON_FIXTURE, Language::Json, 4usize),
        ("pinned.toml", TOML_FIXTURE, Language::Toml, 7),
        ("pinned.yaml", YAML_FIXTURE, Language::Yaml, 6),
        ("deploy.sh", BASH_FIXTURE, Language::Bash, 2),
        ("pinned.xml", XML_FIXTURE, Language::Xml, 5),
        ("icon.svg", SVG_FIXTURE, Language::Xml, 7),
        ("pinned.html", HTML_FIXTURE, Language::Html, 8),
        ("pinned.css", CSS_FIXTURE, Language::Css, 5),
    ] {
        let defs = extract_elements(filename, content, language);
        assert!(
            defs.len() >= min_elements,
            "element-extraction-v1 [{filename}]: expected >= {min_elements} elements, got {}: {defs:#?}",
            defs.len()
        );
        // Names must be unquoted (no JSON `"key"` or TOML/YAML quote residue)
        // — a quoted name would break every name-based lookup downstream.
        for d in &defs {
            assert!(
                !d.name.starts_with('"') && !d.name.starts_with('\''),
                "element-extraction-v1 [{filename}]: element name `{}` must be unquoted",
                d.name
            );
        }
    }
}
