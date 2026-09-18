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
//! - HTML+SVG → script-inner-js-v1: the body of an INLINE `<script>` parses
//!   with the JAVASCRIPT grammar and emits the same `function`/`class`/
//!   `method`/… rows a standalone `.js` file reports, AFTER the owning
//!   script element's row, with `container` = `<hostfilename>#script-N`
//!   (N = 1-based source order over the file's EXTRACTED scripts — external
//!   `src`/`href` scripts, non-JS `type` values and whitespace-only bodies
//!   never become virtual documents and consume no number) and every span
//!   re-based onto FULL-file coordinates so `full_source[bs..be]` is the
//!   symbol's exact source in the host file. A body whose JS parse has
//!   error nodes emits nothing (never fails the file).
//! - LaTeX → `section` per sectioning command (`\part`…`\subparagraph`; the
//!   grammar nests each section's content inside it, so the region spans to
//!   the next sectioning command of equal-or-higher level or `\end{document}`)
//!   + `environment` per `\begin{env}…\end{env}` block (nested environments
//!   recurse; `\newenvironment`/`\newtheorem` and math zones never emit)
//! - Log → `entry` per parsed log entry from the NATIVE scanner
//!   (`ast::logs` — no tree-sitter grammar exists for logs), named after the
//!   normalized level (`error`/`warn`/`info`/`debug`) or `"entry"` for
//!   level-less entries; continuation lines (stack traces) join the entry's
//!   region; signature = the raw timestamp text (or empty). Unlike the
//!   tree-walk formats, entries set `definition_line` = the entry's start
//!   line.
//! - Text → `heading` per heuristic TOC heading from the NATIVE scanner
//!   (`ast::toc` — no tree-sitter grammar exists for prose): setext
//!   (text + `===`/`---` underline, region = BOTH lines), ATX (`#`-prefixed),
//!   ALL-CAPS lines and numbered/word outlines, named after the collapsed
//!   heading text (the `#`/underline/numbering markers stay in the region
//!   bytes but never in the name for setext/ATX; numbered outlines KEEP
//!   their prefix). Signature is always empty; `definition_line` = the
//!   heading's first line. The documented false-positive classes (shouted
//!   prose, decimal numbers reading like outlines) are pinned in `ast::toc`'s
//!   unit tests.
//! - Markdown → `heading` per ATX heading (`#`…`######`) and setext heading
//!   (`text` + `===`/`---` underline), named after the heading text (the
//!   `#`/underline markers are separate grammar children and never enter the
//!   name; region = the heading node itself, NOT content-spanning) +
//!   `code-block` per fenced code block (named after the info string's
//!   `language` token, `"code-block"` when there is none) and per indented
//!   code block (the BLOCK grammar emits a dedicated node kind) +
//!   `table` per pipe table, named after the header-row cells joined with
//!   `" | "`. Paragraphs/lists/block quotes/thematic breaks/HTML blocks/
//!   link reference definitions never emit. Parsed with the tree-sitter-md
//!   BLOCK grammar only — inline spans stay unparsed.
//! - Csv/Tsv → `record` per RFC 4180 record from the NATIVE scanner
//!   (`ast::csvscan` — the only CSV grammar crate on crates.io is
//!   unbuildable, so no tree-sitter grammar is wired), named after the first
//!   field's text truncated to 60 chars (else `row-N`), region = the record's
//!   exact source bytes (delimiters, quotes and embedded newlines included;
//!   the terminating `\n`/`\r\n` excluded) + `cell` per field of the FIRST
//!   record only (the header convention; name = the field's unescaped text,
//!   region = the field's RAW bytes, quotes included). Signature is always
//!   empty; `definition_line` = the record/field's start line.
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
    // definition in source order, `#id`-named wherever an id exists. The ONE
    // exception is the `<style>` body (style-inner-css-v1): `.a { … }` also
    // emits as a `selector` row, right after the owning `style` element.
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
        ("selector", ".a"),
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
    // the void `<br/>` is an element; `body` carries its `#id` name. The
    // style_element's CSS body ALSO emits (style-inner-css-v1): `body { … }`
    // is a `selector` row right after the owning `style` element — the same
    // name as the HTML `<body>` element but a different kind, so the
    // (kind, name) sequence stays unambiguous.
    let sequence: Vec<(String, String)> = defs
        .iter()
        .map(|d| (d.kind.clone(), d.name.clone()))
        .collect();
    let expected: Vec<(String, String)> = [
        ("element", "html"),
        ("element", "head"),
        ("element", "title"),
        ("element", "style"),
        ("selector", "body"),
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
// style-inner CSS (style-inner-css-v1): <style> bodies emit selector/at-rule
// rows re-based onto FULL-file coordinates — html style_element, svg <style>
// (plain + CDATA), whitespace guard, script-inner JS guard
// =============================================================================

/// Mid-file HTML <style>: the element sits at line 4 and the CSS body spans
/// three physical lines, so every inner row's line numbers are FILE lines
/// (line_base = the newlines before the raw_text body) and every byte span
/// slices back against the FULL source — the module's slice-back invariant
/// must hold for inner definitions too. A `<script>` body in the same
/// document emits its element row but NEVER inner-JS rows (documented
/// FUTURE — no code-language walker runs inside embedded scripts).
const HTML_STYLE_INNER_FIXTURE: &str = "<!DOCTYPE html>\n\
                                        <html>\n\
                                        <head>\n\
                                        <style>\n\
                                        body { color: red; }\n\
                                        @media print {\n\
                                        \x20 .p { color: black; }\n\
                                        }\n\
                                        </style>\n\
                                        </head>\n\
                                        <body id=\"main\">\n\
                                        <script>var x = 1;</script>\n\
                                        </body>\n\
                                        </html>\n";

#[test]
fn html_style_inner_css_emits_rebased_selectors_at_rules_and_slices_back() {
    let defs = extract_elements("styled.html", HTML_STYLE_INNER_FIXTURE, Language::Html);
    assert_element_invariants(&defs, "styled.html");

    // Exact sequence: the style element's CSS body emits AFTER the owning
    // element row (selector → at-rule → its nested selector). The `<script>`
    // body contains no extractable JS definitions (`var x = 1;` declares no
    // function/class/constant the unified walk reports), so it contributes
    // nothing beyond its element row.
    let sequence: Vec<(String, String)> = defs
        .iter()
        .map(|d| (d.kind.clone(), d.name.clone()))
        .collect();
    let expected: Vec<(String, String)> = [
        ("element", "html"),
        ("element", "head"),
        ("element", "style"),
        ("selector", "body"),
        ("at-rule", "@media"),
        ("selector", ".p"),
        ("element", "body#main"),
        ("element", "script"),
    ]
    .iter()
    .map(|(k, n)| (k.to_string(), n.to_string()))
    .collect();
    assert_eq!(
        sequence, expected,
        "element-extraction-v1 [styled.html]: expected exact style-inner sequence"
    );

    // Mid-file line offsets: `<style>` opens on line 4, so the inner rows are
    // FILE lines 5/6-7/7 — not the inner tree's 2/3-4/4.
    let body_sel = find_element(&defs, "styled.html", "selector", "body");
    assert_span(body_sel, "styled.html", "selector:body", 5, 5);
    // Byte slice-back against the FULL source: the rebased span is the exact
    // rule text.
    let (bs, be) = (
        body_sel.byte_start.unwrap() as usize,
        body_sel.byte_end.unwrap() as usize,
    );
    assert_eq!(
        &HTML_STYLE_INNER_FIXTURE[bs..be],
        "body { color: red; }",
        "selector:body must slice back to the exact rule text"
    );

    let media = find_element(&defs, "styled.html", "at-rule", "@media");
    assert_span(media, "styled.html", "at-rule:@media", 6, 8);
    let (ms, me) = (
        media.byte_start.unwrap() as usize,
        media.byte_end.unwrap() as usize,
    );
    assert!(
        HTML_STYLE_INNER_FIXTURE[ms..me].starts_with("@media print {"),
        "at-rule:@media must slice back to the at-rule source, got {:?}",
        &HTML_STYLE_INNER_FIXTURE[ms..me]
    );

    let p = find_element(&defs, "styled.html", "selector", ".p");
    assert_span(p, "styled.html", "selector:.p", 7, 7);
    let (ps, pe) = (p.byte_start.unwrap() as usize, p.byte_end.unwrap() as usize);
    assert_eq!(
        &HTML_STYLE_INNER_FIXTURE[ps..pe],
        ".p { color: black; }",
        "selector:.p must slice back to the exact nested rule text"
    );
}

/// SVG `<style>` in both spellings the XML grammar produces (verified
/// empirically against tree-sitter-xml 0.7.0): a plain body is a `CharData`
/// child of the style element's `content`, and a CDATA-wrapped body is
/// `content` → `CDSect` → `CData`. Both must emit, with full-file spans.
const SVG_STYLE_INNER_FIXTURE: &str = "<svg xmlns=\"http://www.w3.org/2000/svg\">\n\
                                       <defs>\n\
                                       <style>\n\
                                       .a { fill: red; }\n\
                                       </style>\n\
                                       </defs>\n\
                                       <style><![CDATA[\n\
                                       #b circle { stroke: blue; }\n\
                                       ]]></style>\n\
                                       </svg>\n";

#[test]
fn svg_style_inner_css_emits_from_chardata_and_cdata_bodies() {
    let defs = extract_elements("icon2.svg", SVG_STYLE_INNER_FIXTURE, Language::Xml);
    assert_element_invariants(&defs, "icon2.svg");

    let sequence: Vec<(String, String)> = defs
        .iter()
        .map(|d| (d.kind.clone(), d.name.clone()))
        .collect();
    let expected: Vec<(String, String)> = [
        ("element", "svg"),
        ("element", "defs"),
        ("element", "style"),
        ("selector", ".a"),
        ("element", "style"),
        ("selector", "#b circle"),
    ]
    .iter()
    .map(|(k, n)| (k.to_string(), n.to_string()))
    .collect();
    assert_eq!(
        sequence, expected,
        "element-extraction-v1 [icon2.svg]: expected both style bodies to emit"
    );

    // Plain CharData body (line 4, mid-file): full-file line + byte slice-back.
    let a = find_element(&defs, "icon2.svg", "selector", ".a");
    assert_span(a, "icon2.svg", "selector:.a", 4, 4);
    let (as_, ae) = (a.byte_start.unwrap() as usize, a.byte_end.unwrap() as usize);
    assert_eq!(
        &SVG_STYLE_INNER_FIXTURE[as_..ae],
        ".a { fill: red; }",
        "selector:.a must slice back to the exact rule text"
    );

    // CDATA body (lines 8): the CDSect-wrapped CData chunk also rebases.
    let b = find_element(&defs, "icon2.svg", "selector", "#b circle");
    assert_span(b, "icon2.svg", "selector:#b circle", 8, 8);
    let (bs, be) = (b.byte_start.unwrap() as usize, b.byte_end.unwrap() as usize);
    assert_eq!(
        &SVG_STYLE_INNER_FIXTURE[bs..be],
        "#b circle { stroke: blue; }",
        "selector:#b circle must slice back to the exact rule text"
    );
}

#[test]
fn whitespace_only_style_body_and_definition_free_script_body_emit_no_inner_rows() {
    // Whitespace-only <style> body: the element rows still emit, no CSS rows
    // (and no wasted parse). The script body declares nothing the JS
    // definition walk reports (`var x = 1;`), so it stays inert too; the
    // guards for EXTERNAL / non-JS / syntax-broken scripts are pinned in
    // the script-inner-js-v1 tests below.
    let src = "<html>\n<style>\n   \n</style>\n<script>\nvar x = 1;\n</script>\n</html>\n";
    let defs = extract_elements("guarded.html", src, Language::Html);
    assert_element_invariants(&defs, "guarded.html");

    let sequence: Vec<(String, String)> = defs
        .iter()
        .map(|d| (d.kind.clone(), d.name.clone()))
        .collect();
    let expected: Vec<(String, String)> = [
        ("element", "html"),
        ("element", "style"),
        ("element", "script"),
    ]
    .iter()
    .map(|(k, n)| (k.to_string(), n.to_string()))
    .collect();
    assert_eq!(
        sequence, expected,
        "element-extraction-v1 [guarded.html]: whitespace style + script inner stay inert"
    );
}

// =============================================================================
// script-inner JS (script-inner-js-v1): inline <script> bodies emit JS
// definitions as virtual documents `<host>#script-N` — spans re-based onto
// FULL-file coordinates, external/non-JS/broken scripts skipped
// =============================================================================

/// Find a VIRTUAL-SCRIPT definition by kind + name + container, dumping the
/// full list on miss so a RED run reads as a report.
fn find_virtual<'a>(
    defs: &'a [DefinitionInfo],
    file: &str,
    kind: &str,
    name: &str,
    container: &str,
) -> &'a DefinitionInfo {
    defs.iter()
        .find(|d| d.kind == kind && d.name == name && d.container.as_deref() == Some(container))
        .unwrap_or_else(|| {
            panic!(
                "element-extraction-v1 [{file}]: virtual definition {kind}:`{name}` \
                 (container {container}) not found.\nExtracted definitions ({})=\n{defs:#?}",
                defs.len()
            )
        })
}

/// Two mid-file inline scripts (a function + a class with two methods): the
/// JS rows land AFTER the owning script element's row in source order, every
/// line number is a FILE line (line_base = the newlines before the body),
/// every byte span slices back to the symbol's EXACT source inside the host
/// HTML, and each row carries its virtual document's `#script-N` name.
const HTML_SCRIPT_INNER_FIXTURE: &str = "<!DOCTYPE html>\n\
                                         <html>\n\
                                         <head><title>Demo</title></head>\n\
                                         <body>\n\
                                         <script>\n\
                                         function sayHi(name) {\n\
                                         \x20 return \"hi \" + name;\n\
                                         }\n\
                                         </script>\n\
                                         <p>Text</p>\n\
                                         <script>\n\
                                         class Counter {\n\
                                         \x20 constructor() { this.n = 0; }\n\
                                         \x20 increment() { this.n += 1; }\n\
                                         }\n\
                                         </script>\n\
                                         </body>\n\
                                         </html>\n";

#[test]
fn html_inline_scripts_emit_js_definitions_as_rebased_virtual_documents() {
    let defs = extract_elements("page.html", HTML_SCRIPT_INNER_FIXTURE, Language::Html);

    // EXACT source-order sequence: element rows keep their pre-order places
    // and each script's JS rows follow its own `script` element row.
    let sequence: Vec<(String, String, Option<String>)> = defs
        .iter()
        .map(|d| (d.kind.clone(), d.name.clone(), d.container.clone()))
        .collect();
    let expected: Vec<(String, String, Option<String>)> = [
        ("element", "html", None),
        ("element", "head", None),
        ("element", "title", None),
        ("element", "body", None),
        ("element", "script", None),
        ("function", "sayHi", Some("page.html#script-1")),
        ("element", "p", None),
        ("element", "script", None),
        ("class", "Counter", Some("page.html#script-2")),
        ("method", "constructor", Some("page.html#script-2")),
        ("method", "increment", Some("page.html#script-2")),
    ]
    .iter()
    .map(|(k, n, c)| (k.to_string(), n.to_string(), c.map(str::to_string)))
    .collect();
    assert_eq!(
        sequence, expected,
        "element-extraction-v1 [page.html]: expected exact element/JS sequence"
    );

    // Host element rows carry NO provenance; script rows name their document.
    // (pinned by the container column of the sequence above)

    // Mid-file line offsets: script 1's body starts on line 5, so the JS
    // tree's line 2 is FILE line 6.
    let say_hi = find_virtual(
        &defs,
        "page.html",
        "function",
        "sayHi",
        "page.html#script-1",
    );
    assert_span(say_hi, "page.html", "function:sayHi", 6, 8);
    assert_eq!(
        say_hi.definition_line,
        Some(6),
        "definition_line must translate onto the file's declaration line"
    );
    assert_eq!(
        say_hi.signature, "function sayHi(name) {",
        "signature stays the JS signature"
    );
    // Byte slice-back against the FULL source: the rebased span is the exact
    // symbol text inside the HTML.
    let (ss, se) = (
        say_hi.byte_start.unwrap() as usize,
        say_hi.byte_end.unwrap() as usize,
    );
    assert_eq!(
        &HTML_SCRIPT_INNER_FIXTURE[ss..se],
        "function sayHi(name) {\n  return \"hi \" + name;\n}",
        "function:sayHi must slice back to the exact JS source in the host file"
    );

    // Script 2 (lines 11-16): class + methods, all in #script-2.
    let counter = find_virtual(&defs, "page.html", "class", "Counter", "page.html#script-2");
    assert_span(counter, "page.html", "class:Counter", 12, 15);
    assert_eq!(counter.definition_line, Some(12));
    let (cs, ce) = (
        counter.byte_start.unwrap() as usize,
        counter.byte_end.unwrap() as usize,
    );
    assert_eq!(
        &HTML_SCRIPT_INNER_FIXTURE[cs..ce],
        "class Counter {\n  constructor() { this.n = 0; }\n  increment() { this.n += 1; }\n}",
        "class:Counter must slice back to the exact JS source in the host file"
    );

    let ctor = find_virtual(
        &defs,
        "page.html",
        "method",
        "constructor",
        "page.html#script-2",
    );
    assert_span(ctor, "page.html", "method:constructor", 13, 13);
    let (os, oe) = (
        ctor.byte_start.unwrap() as usize,
        ctor.byte_end.unwrap() as usize,
    );
    assert_eq!(
        &HTML_SCRIPT_INNER_FIXTURE[os..oe],
        "constructor() { this.n = 0; }",
        "method:constructor must slice back to the exact JS source in the host file"
    );

    let inc = find_virtual(
        &defs,
        "page.html",
        "method",
        "increment",
        "page.html#script-2",
    );
    assert_span(inc, "page.html", "method:increment", 14, 14);
}

/// Guards: an external `src` script and a non-JS `type` never become virtual
/// documents (only their element rows emit), a syntax-broken script emits
/// nothing, and none of them consume a `#script-N` number — the numbering
/// stays contiguous over the file's EXTRACTED scripts. One bad script never
/// fails the file: the good scripts around it still emit.
const HTML_SCRIPT_GUARDS_FIXTURE: &str = "<!DOCTYPE html>\n\
                                          <html>\n\
                                          <body>\n\
                                          <script src=\"app.js\"></script>\n\
                                          <script type=\"application/json\">{\"a\": 1}</script>\n\
                                          <script type=\"module\">\n\
                                          export function good() {\n\
                                          \x20 return 1;\n\
                                          }\n\
                                          </script>\n\
                                          <script>\n\
                                          function broken( { oops\n\
                                          </script>\n\
                                          <script>\n\
                                          function second() {\n\
                                          \x20 return 2;\n\
                                          }\n\
                                          </script>\n\
                                          </body>\n\
                                          </html>\n";

#[test]
fn html_external_non_js_and_broken_scripts_are_not_virtual_documents() {
    let defs = extract_elements("guards.html", HTML_SCRIPT_GUARDS_FIXTURE, Language::Html);

    // The external script, the JSON script and the broken script keep only
    // their element rows; the module script and the good plain script emit.
    // Numbering is contiguous over the EXTRACTED scripts: `good` is #script-1
    // (the two skipped scripts consumed no number) and `second` is #script-2.
    let sequence: Vec<(String, String, Option<String>)> = defs
        .iter()
        .map(|d| (d.kind.clone(), d.name.clone(), d.container.clone()))
        .collect();
    let expected: Vec<(String, String, Option<String>)> = [
        ("element", "html", None),
        ("element", "body", None),
        ("element", "script", None),
        ("element", "script", None),
        ("element", "script", None),
        ("function", "good", Some("guards.html#script-1")),
        ("element", "script", None),
        ("element", "script", None),
        ("function", "second", Some("guards.html#script-2")),
    ]
    .iter()
    .map(|(k, n, c)| (k.to_string(), n.to_string(), c.map(str::to_string)))
    .collect();
    assert_eq!(
        sequence, expected,
        "element-extraction-v1 [guards.html]: external/non-JS/broken scripts stay inert"
    );

    let good = find_virtual(
        &defs,
        "guards.html",
        "function",
        "good",
        "guards.html#script-1",
    );
    assert_span(good, "guards.html", "function:good", 7, 9);
    let (gs, ge) = (
        good.byte_start.unwrap() as usize,
        good.byte_end.unwrap() as usize,
    );
    assert_eq!(
        &HTML_SCRIPT_GUARDS_FIXTURE[gs..ge],
        "function good() {\n  return 1;\n}",
        "the byte span is the JS declaration NODE — the `export ` token stays outside it \
         (the line span keeps the wrapper/trivia semantics)"
    );

    let second = find_virtual(
        &defs,
        "guards.html",
        "function",
        "second",
        "guards.html#script-2",
    );
    assert_span(second, "guards.html", "function:second", 15, 17);
}

/// SVG `<script>` bodies in both spellings the XML grammar produces (the same
/// shape family as the style-inner CSS batches): a plain body is a `CharData`
/// child of the script element's `content`, a CDATA-wrapped body is
/// `content` → `CDSect` → `CData`. Both become virtual documents with
/// full-file spans.
const SVG_SCRIPT_INNER_FIXTURE: &str = "<svg xmlns=\"http://www.w3.org/2000/svg\">\n\
                                        <script><![CDATA[\n\
                                        function boot() {\n\
                                        \x20 return 1;\n\
                                        }\n\
                                        ]]></script>\n\
                                        <script type=\"text/ecmascript\">\n\
                                        function go(n) {\n\
                                        \x20 return n + 1;\n\
                                        }\n\
                                        </script>\n\
                                        <script href=\"lib.js\"/>\n\
                                        </svg>\n";

#[test]
fn svg_script_bodies_emit_from_chardata_and_cdata_bodies() {
    let defs = extract_elements("chart.svg", SVG_SCRIPT_INNER_FIXTURE, Language::Xml);

    // CDATA script → #script-1, plain ecmascript script → #script-2; the
    // external `<script href="lib.js"/>` (self-closing) keeps only its
    // element row.
    let sequence: Vec<(String, String, Option<String>)> = defs
        .iter()
        .map(|d| (d.kind.clone(), d.name.clone(), d.container.clone()))
        .collect();
    let expected: Vec<(String, String, Option<String>)> = [
        ("element", "svg", None),
        ("element", "script", None),
        ("function", "boot", Some("chart.svg#script-1")),
        ("element", "script", None),
        ("function", "go", Some("chart.svg#script-2")),
        ("element", "script", None),
    ]
    .iter()
    .map(|(k, n, c)| (k.to_string(), n.to_string(), c.map(str::to_string)))
    .collect();
    assert_eq!(
        sequence, expected,
        "element-extraction-v1 [chart.svg]: expected both script bodies to emit"
    );

    // CDATA body: the CDSect-wrapped CData chunk rebases onto FILE lines 3-5.
    let boot = find_virtual(&defs, "chart.svg", "function", "boot", "chart.svg#script-1");
    assert_span(boot, "chart.svg", "function:boot", 3, 5);
    let (bs, be) = (
        boot.byte_start.unwrap() as usize,
        boot.byte_end.unwrap() as usize,
    );
    assert_eq!(
        &SVG_SCRIPT_INNER_FIXTURE[bs..be],
        "function boot() {\n  return 1;\n}",
        "function:boot must slice back to the exact JS source in the SVG"
    );

    // Plain CharData body: lines 8-10.
    let go = find_virtual(&defs, "chart.svg", "function", "go", "chart.svg#script-2");
    assert_span(go, "chart.svg", "function:go", 8, 10);
    let (gs, ge) = (
        go.byte_start.unwrap() as usize,
        go.byte_end.unwrap() as usize,
    );
    assert_eq!(
        &SVG_SCRIPT_INNER_FIXTURE[gs..ge],
        "function go(n) {\n  return n + 1;\n}",
        "function:go must slice back to the exact JS source in the SVG"
    );
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
// LaTeX — content-spanning sections + begin/end environments (nested recurse)
// =============================================================================

const LATEX_FIXTURE: &str = r#"\documentclass{article}
\usepackage{amsmath}

\begin{document}

\section{Introduction}
This is the intro.

\subsection{Details}
Some details here.
\begin{equation}
  E = mc^2
\end{equation}

\begin{itemize}
  \item first
  \item second
\end{itemize}

\section{Method}
\label{sec:method}
Body of method.

\end{document}
"#;

#[test]
fn latex_sections_span_content_and_environments_recurse() {
    let defs = extract_elements("pinned.tex", LATEX_FIXTURE, Language::Latex);
    assert_element_invariants(&defs, "pinned.tex");

    // EXACT source-order sequence (pre-order = source order): the document
    // environment first, then each section BEFORE its nested content. The
    // `\label`, `\documentclass`, `\usepackage` and body text never emit.
    let sequence: Vec<(String, String)> = defs
        .iter()
        .map(|d| (d.kind.clone(), d.name.clone()))
        .collect();
    let expected: Vec<(String, String)> = [
        ("environment", "document"),
        ("section", "Introduction"),
        ("section", "Details"),
        ("environment", "equation"),
        ("environment", "itemize"),
        ("section", "Method"),
    ]
    .iter()
    .map(|(k, n)| (k.to_string(), n.to_string()))
    .collect();
    assert_eq!(
        sequence, expected,
        "element-extraction-v1 [pinned.tex]: expected exact section/environment sequence"
    );

    // SECTION REGION SEMANTICS: the grammar nests each section's content
    // inside the sectioning node, so a section spans everything until the
    // next sectioning command of equal-or-higher level (or \end{document}).
    // `Introduction` (line 6) owns its content, the Details subsection and
    // the equation/itemize environments, ending on the line BEFORE
    // `\section{Method}` (line 19) — i.e. the `\end{itemize}` line 18.
    let intro = find_element(&defs, "pinned.tex", "section", "Introduction");
    assert_span(intro, "pinned.tex", "section:Introduction", 6, 18);
    assert_byte_slice(
        intro,
        LATEX_FIXTURE,
        "pinned.tex",
        "\\section{Introduction}",
    );

    // The last section runs up to `\end{document}` but does not swallow the
    // trailing blank line — the node ends with its last content line.
    let method = find_element(&defs, "pinned.tex", "section", "Method");
    assert_span(method, "pinned.tex", "section:Method", 20, 22);
    assert_byte_slice(method, LATEX_FIXTURE, "pinned.tex", "\\section{Method}");

    // The subsection is nested INSIDE Introduction's span (grammar-provided
    // hierarchy) and carries its own definition.
    let details = find_element(&defs, "pinned.tex", "section", "Details");
    assert_span(details, "pinned.tex", "section:Details", 9, 18);
    assert_byte_slice(
        details,
        LATEX_FIXTURE,
        "pinned.tex",
        "\\subsection{Details}",
    );

    // Environments span begin..end, nested inside their sections.
    let document = find_element(&defs, "pinned.tex", "environment", "document");
    assert_span(document, "pinned.tex", "environment:document", 4, 24);
    assert_byte_slice(document, LATEX_FIXTURE, "pinned.tex", "\\begin{document}");

    let equation = find_element(&defs, "pinned.tex", "environment", "equation");
    assert_span(equation, "pinned.tex", "environment:equation", 11, 13);
    assert_byte_slice(equation, LATEX_FIXTURE, "pinned.tex", "\\begin{equation}");

    let itemize = find_element(&defs, "pinned.tex", "environment", "itemize");
    assert_span(itemize, "pinned.tex", "environment:itemize", 15, 18);
    assert_byte_slice(itemize, LATEX_FIXTURE, "pinned.tex", "\\begin{itemize}");
}

// =============================================================================
// Log — native entry scanner (NO tree-sitter): entries as definitions
// =============================================================================
//
// `.log` never reaches a tree-sitter tree (no grammar exists). The
// `get_code_structure` hook early-returns to the `ast::logs` scanner, and
// each entry maps onto `DefinitionInfo` with kind `"entry"`, name =
// normalized level (or `"entry"` for level-less entries), signature = the
// raw timestamp (or empty), and definition_line = the entry's first line.
// `assert_element_invariants` is deliberately NOT applied here: log entries
// DO set `definition_line` (the entry's start line is its declaration line).

const LOG_FIXTURE: &str = "\
boot garbage line
2026-09-14T08:34:49Z INFO service started
2026-09-14T08:34:50Z ERROR query failed
Traceback (most recent call last):
  File \"db.py\", line 42, in query
2026-09-14 08:35:01,123 WARN slow query
[error] disk usage 91%
2026-09-14T08:36:00Z INFO healthy
";

#[test]
fn log_entries_are_definitions_with_exact_spans() {
    let defs = extract_elements("server.log", LOG_FIXTURE, Language::Log);

    // EXACT source-order sequence: level-led name for timestamped entries,
    // bare "entry" for the leading garbage line.
    let sequence: Vec<(String, String)> = defs
        .iter()
        .map(|d| (d.kind.clone(), d.name.clone()))
        .collect();
    let expected: Vec<(String, String)> = [
        ("entry", "entry"),
        ("entry", "info"),
        ("entry", "error"),
        ("entry", "warn"),
        ("entry", "error"),
        ("entry", "info"),
    ]
    .iter()
    .map(|(k, n)| (k.to_string(), n.to_string()))
    .collect();
    assert_eq!(
        sequence, expected,
        "element-extraction-v1 [server.log]: expected exact entry sequence"
    );

    // Every entry sets definition_line = its start line, and carries byte
    // spans (the format-tier contract).
    for d in &defs {
        assert_eq!(
            d.definition_line,
            Some(d.line_start),
            "element-extraction-v1 [server.log]: {}:`{}` definition_line must be the start line",
            d.kind,
            d.name
        );
        assert!(
            d.byte_start.is_some() && d.byte_end.is_some(),
            "element-extraction-v1 [server.log]: {}:`{}` must carry byte spans",
            d.kind,
            d.name
        );
    }

    // Leading garbage: level-less, timestamp-less, single line.
    let garbage = find_element(&defs, "server.log", "entry", "entry");
    assert_span(garbage, "server.log", "entry:entry", 1, 1);
    assert_eq!(
        garbage.signature, "",
        "garbage has no timestamp → empty signature"
    );

    // INFO entry: signature = the raw timestamp text.
    let info = find_element(&defs, "server.log", "entry", "info");
    assert_span(info, "server.log", "entry:info", 2, 2);
    assert_eq!(info.signature, "2026-09-14T08:34:49Z");

    // ERROR entry: the stack-trace continuation lines attach (lines 4-5),
    // so the span covers the whole event region.
    let error = find_element(&defs, "server.log", "entry", "error");
    assert_span(error, "server.log", "entry:error", 3, 5);
    assert_eq!(error.signature, "2026-09-14T08:34:50Z");
    let line3_start = LOG_FIXTURE.find("2026-09-14T08:34:50Z").unwrap();
    let line6_start = LOG_FIXTURE.find("2026-09-14 08:35:01,123").unwrap();
    assert_eq!(error.byte_start, Some(line3_start as u64));
    // byte_end is exclusive of line 5's trailing newline.
    assert_eq!(error.byte_end, Some((line6_start - 1) as u64));
    let slice = &LOG_FIXTURE[line3_start..line6_start - 1];
    assert!(
        slice.contains("Traceback"),
        "region must cover the continuation"
    );
    assert!(slice.contains("db.py"), "region must cover the stack frame");

    // WARN entry: space-separated datetime with comma millis as signature.
    let warn = find_element(&defs, "server.log", "entry", "warn");
    assert_span(warn, "server.log", "entry:warn", 6, 6);
    assert_eq!(warn.signature, "2026-09-14 08:35:01,123");

    // Bracket-level entry: level-led, no timestamp → empty signature. Two
    // entries share the name `error`, so select this one by its line.
    let bracket = defs
        .iter()
        .find(|d| d.kind == "entry" && d.name == "error" && d.line_start == 7)
        .unwrap_or_else(|| {
            panic!(
                "element-extraction-v1 [server.log]: bracket error entry (line 7) not found.\n{defs:#?}"
            )
        });
    assert_span(bracket, "server.log", "entry:error(bracket)", 7, 7);
    assert_eq!(bracket.signature, "");
}

// =============================================================================
// Plain text — heuristic TOC scanner (NO tree-sitter): headings as definitions
// =============================================================================
//
// `.txt` never reaches a tree-sitter tree (prose has no syntax to parse).
// The `get_code_structure` hook early-returns to the `ast::toc` scanner, and
// each heading maps onto `DefinitionInfo` with kind `"heading"`, name =
// collapsed heading text, signature = empty, and definition_line = the
// heading's first line. `assert_element_invariants` is deliberately NOT
// applied here: text headings DO set `definition_line` (the heading's start
// line is its declaration line).
//
// Line map (the pinned spans below are computed against exactly this text):
//  1: USER GUIDE
//  2:
//  3: Introduction
//  4: ============
//  5:
//  6: ## Quick Start
//  7:
//  8: 1. Setup
//  9: 1.1. Requirements
// 10:
// 11: lowercase prose stays inert
// 12: SEE ALSO:
// 13:
// 14: Appendix 2
const TEXT_FIXTURE: &str = "\
USER GUIDE

Introduction
============

## Quick Start

1. Setup
1.1. Requirements

lowercase prose stays inert
SEE ALSO:

Appendix 2
";

#[test]
fn text_toc_headings_are_definitions_with_exact_spans() {
    let defs = extract_elements("notes.txt", TEXT_FIXTURE, Language::Text);

    // EXACT source-order sequence: the ALL-CAPS title, the setext heading
    // (both lines), the ATX heading, the numbered outlines (prefix kept in
    // the name), and the word outline. Lowercase prose and the
    // colon-terminated `SEE ALSO:` label line never emit.
    let sequence: Vec<(String, String)> = defs
        .iter()
        .map(|d| (d.kind.clone(), d.name.clone()))
        .collect();
    let expected: Vec<(String, String)> = [
        ("heading", "USER GUIDE"),
        ("heading", "Introduction"),
        ("heading", "Quick Start"),
        ("heading", "1. Setup"),
        ("heading", "1.1. Requirements"),
        ("heading", "Appendix 2"),
    ]
    .iter()
    .map(|(k, n)| (k.to_string(), n.to_string()))
    .collect();
    assert_eq!(
        sequence, expected,
        "element-extraction-v1 [notes.txt]: expected exact heading sequence"
    );

    // Every heading: signature empty, definition_line = start line, byte
    // spans present, and the byte region is an exact slice of the source.
    for d in &defs {
        assert_eq!(d.kind, "heading");
        assert!(
            d.signature.is_empty(),
            "element-extraction-v1 [notes.txt]: prose has no signatures"
        );
        assert_eq!(
            d.definition_line,
            Some(d.line_start),
            "element-extraction-v1 [notes.txt]: {} definition_line must be the start line",
            d.name
        );
        assert!(
            d.byte_start.is_some() && d.byte_end.is_some(),
            "element-extraction-v1 [notes.txt]: {} must carry byte spans",
            d.name
        );
        let (s, e) = (d.byte_start.unwrap() as usize, d.byte_end.unwrap() as usize);
        assert!(e > s);
        let _ = &TEXT_FIXTURE[s..e];
    }

    // ALL-CAPS title: single line, region = the physical line.
    let title = find_element(&defs, "notes.txt", "heading", "USER GUIDE");
    assert_span(title, "notes.txt", "heading:USER GUIDE", 1, 1);
    assert_byte_slice(title, TEXT_FIXTURE, "notes.txt", "USER GUIDE");

    // Setext heading: region covers text + underline exactly.
    let setext = find_element(&defs, "notes.txt", "heading", "Introduction");
    assert_span(setext, "notes.txt", "heading:Introduction", 3, 4);
    assert_byte_slice(setext, TEXT_FIXTURE, "notes.txt", "Introduction");
    let setext_slice =
        &TEXT_FIXTURE[setext.byte_start.unwrap() as usize..setext.byte_end.unwrap() as usize];
    assert_eq!(
        setext_slice, "Introduction\n============",
        "setext region = heading line + underline line"
    );

    // ATX heading: name has the markers stripped, region keeps them.
    let atx = find_element(&defs, "notes.txt", "heading", "Quick Start");
    assert_span(atx, "notes.txt", "heading:Quick Start", 6, 6);
    assert_byte_slice(atx, TEXT_FIXTURE, "notes.txt", "## Quick Start");

    // Numbered outline: prefix stays in the name AND in the region.
    let setup = find_element(&defs, "notes.txt", "heading", "1. Setup");
    assert_span(setup, "notes.txt", "heading:1. Setup", 8, 8);
    assert_byte_slice(setup, TEXT_FIXTURE, "notes.txt", "1. Setup");

    let sub = find_element(&defs, "notes.txt", "heading", "1.1. Requirements");
    assert_span(sub, "notes.txt", "heading:1.1. Requirements", 9, 9);
    assert_byte_slice(sub, TEXT_FIXTURE, "notes.txt", "1.1. Requirements");

    // Section word: `Appendix 2` (the numeral rule).
    let appendix = find_element(&defs, "notes.txt", "heading", "Appendix 2");
    assert_span(appendix, "notes.txt", "heading:Appendix 2", 14, 14);
    assert_byte_slice(appendix, TEXT_FIXTURE, "notes.txt", "Appendix 2");
}

// =============================================================================
// Markdown — headings (ATX + setext), fenced/indented code blocks, pipe table
// =============================================================================

// Line map (the pinned spans below are computed against exactly this text):
//  1: # Top Level
//  2:
//  3: Body text under the title is NOT an element.
//  4:
//  5: ## Details
//  6:
//  7: ```rust
//  8: fn main() {}
//  9: ```
// 10:
// 11: Setext Heading
// 12: ==============
// 13:
// 14: ```
// 15: plain fence, no language token
// 16: ```
// 17:
// 18: | Column A | Column B |
// 19: | -------- | -------- |
// 20: | value 1  | value 2  |
// 21:
// 22: - a list item
// 23: > a block quote
// 24:
// 25:     indented code line one
// 26:     indented code line two
const MARKDOWN_FIXTURE: &str = "\
# Top Level

Body text under the title is NOT an element.

## Details

```rust
fn main() {}
```

Setext Heading
==============

```
plain fence, no language token
```

| Column A | Column B |
| -------- | -------- |
| value 1  | value 2  |

- a list item
> a block quote

    indented code line one
    indented code line two
";

#[test]
fn markdown_headings_code_blocks_and_tables_are_elements() {
    let defs = extract_elements("README.md", MARKDOWN_FIXTURE, Language::Markdown);
    assert_element_invariants(&defs, "README.md");

    // EXACT source-order sequence: paragraphs, the list, the block quote and
    // front-matter-style prose never emit. The setext heading sits BETWEEN
    // the rust fenced block and the plain fenced block.
    let sequence: Vec<(String, String)> = defs
        .iter()
        .map(|d| (d.kind.clone(), d.name.clone()))
        .collect();
    let expected: Vec<(String, String)> = [
        ("heading", "Top Level"),
        ("heading", "Details"),
        ("code-block", "rust"),
        ("heading", "Setext Heading"),
        ("code-block", "code-block"),
        ("table", "Column A | Column B"),
        ("code-block", "code-block"),
    ]
    .iter()
    .map(|(k, n)| (k.to_string(), n.to_string()))
    .collect();
    assert_eq!(
        sequence, expected,
        "element-extraction-v1 [README.md]: expected exact markdown element sequence"
    );

    // ATX heading: region = the heading node itself (the `# Top Level`
    // line), NOT content-spanning — the markdown block grammar keeps
    // content in sibling nodes, unlike LaTeX's nested sections.
    let top = find_element(&defs, "README.md", "heading", "Top Level");
    assert_span(top, "README.md", "heading:Top Level", 1, 1);
    assert_byte_slice(top, MARKDOWN_FIXTURE, "README.md", "# Top Level");
    let top_slice =
        &MARKDOWN_FIXTURE[top.byte_start.unwrap() as usize..top.byte_end.unwrap() as usize];
    assert_eq!(
        top_slice, "# Top Level\n",
        "ATX region is exactly its own line (+newline)"
    );

    // The ```rust fence names after its info-string `language` token and
    // spans BOTH fence lines.
    let rust = find_element(&defs, "README.md", "code-block", "rust");
    assert_span(rust, "README.md", "code-block:rust", 7, 9);
    assert_byte_slice(rust, MARKDOWN_FIXTURE, "README.md", "```rust");

    // Setext heading: the region covers the heading lines + underline; the
    // name comes from the `heading_content` paragraph alone (the underline
    // is a sibling child and never enters the name).
    let setext = find_element(&defs, "README.md", "heading", "Setext Heading");
    assert_span(setext, "README.md", "heading:Setext Heading", 11, 12);
    assert_byte_slice(setext, MARKDOWN_FIXTURE, "README.md", "Setext Heading");
    let setext_slice =
        &MARKDOWN_FIXTURE[setext.byte_start.unwrap() as usize..setext.byte_end.unwrap() as usize];
    assert_eq!(
        setext_slice, "Setext Heading\n==============\n",
        "setext region = heading lines + underline"
    );

    // Plain fenced block: no language token → "code-block".
    let plain = find_element(&defs, "README.md", "code-block", "code-block");
    assert_span(plain, "README.md", "code-block:fenced-plain", 14, 16);
    assert_byte_slice(plain, MARKDOWN_FIXTURE, "README.md", "```");

    // Pipe table: name = header cells joined with " | ", delimiter row
    // ignored; region = the whole pipe_table node (header through last row).
    let table = find_element(&defs, "README.md", "table", "Column A | Column B");
    assert_span(table, "README.md", "table:Column A | Column B", 18, 20);
    assert_byte_slice(table, MARKDOWN_FIXTURE, "README.md", "| Column A |");

    // The indented code block shares the "code-block" name with the plain
    // fence — select it by its line (25) and pin its span.
    let indented = defs
        .iter()
        .find(|d| d.kind == "code-block" && d.name == "code-block" && d.line_start == 25)
        .unwrap_or_else(|| {
            panic!(
                "element-extraction-v1 [README.md]: indented code block (line 25) not found.\n{defs:#?}"
            )
        });
    assert_span(indented, "README.md", "code-block:indented", 25, 26);
    assert_byte_slice(
        indented,
        MARKDOWN_FIXTURE,
        "README.md",
        "    indented code line one",
    );
}

// =============================================================================
// CSV/TSV — native RFC 4180 scanner (NO tree-sitter): records + header cells
// =============================================================================
//
// `.csv`/`.tsv` never reach a tree-sitter tree (the only CSV grammar crate on
// crates.io is unbuildable — cc build-dep conflict with ts 0.25 + no bridge
// LanguageFns; root Cargo.toml audit note). The `get_code_structure` hook
// early-returns to the `ast::csvscan` scanner, and each record maps onto a
// `DefinitionInfo` with kind `"record"` (name = first field text truncated to
// 60 chars, else `row-N`), while the FIRST record's fields additionally map
// onto kind `"cell"` definitions (the header convention). `signature` is
// always empty (a data row has nothing signature-shaped) and
// `definition_line` = the record/field's start line.
// `assert_element_invariants` is deliberately NOT applied here: CSV elements
// DO set `definition_line`.
//
// Line map (the pinned spans below are computed against exactly this text):
//  1: sku,product,notes
//  2: A-1,Widget,"round, blue"
//  3: A-2,Gadget,"sells
//  4: well, sometimes"
//  5: A-3,Doodad,plain
const CSV_FIXTURE: &str = "sku,product,notes\n\
                           A-1,Widget,\"round, blue\"\n\
                           A-2,Gadget,\"sells\n\
                           well, sometimes\"\n\
                           A-3,Doodad,plain\n";

#[test]
fn csv_records_and_header_cells_are_definitions_with_exact_spans() {
    let defs = extract_elements("data.csv", CSV_FIXTURE, Language::Csv);

    // EXACT source-order sequence: the header record (whose cells follow it),
    // then one record per data row — record 2 spans two lines (its quoted
    // `notes` field embeds a newline AND a comma).
    let sequence: Vec<(String, String)> = defs
        .iter()
        .map(|d| (d.kind.clone(), d.name.clone()))
        .collect();
    let expected: Vec<(String, String)> = [
        ("record", "sku"),
        ("cell", "sku"),
        ("cell", "product"),
        ("cell", "notes"),
        ("record", "A-1"),
        ("record", "A-2"),
        ("record", "A-3"),
    ]
    .iter()
    .map(|(k, n)| (k.to_string(), n.to_string()))
    .collect();
    assert_eq!(
        sequence, expected,
        "element-extraction-v1 [data.csv]: expected exact record/cell sequence"
    );

    // Every element: definition_line = start line, byte spans present, and
    // the byte region is an exact slice of the source.
    for d in &defs {
        assert_eq!(
            d.definition_line,
            Some(d.line_start),
            "element-extraction-v1 [data.csv]: {}:`{}` definition_line must be the start line",
            d.kind,
            d.name
        );
        assert!(
            d.byte_start.is_some() && d.byte_end.is_some(),
            "element-extraction-v1 [data.csv]: {}:`{}` must carry byte spans",
            d.kind,
            d.name
        );
        assert!(
            d.signature.is_empty(),
            "element-extraction-v1 [data.csv]: {}:`{}` data rows have no signatures",
            d.kind,
            d.name
        );
    }

    // Header record: one line, its cells are sub-regions of its span.
    let header = find_element(&defs, "data.csv", "record", "sku");
    assert_span(header, "data.csv", "record:sku", 1, 1);
    let header_slice =
        &CSV_FIXTURE[header.byte_start.unwrap() as usize..header.byte_end.unwrap() as usize];
    assert_eq!(header_slice, "sku,product,notes", "header region = row 1");

    let cell_sku = find_element(&defs, "data.csv", "cell", "sku");
    assert_span(cell_sku, "data.csv", "cell:sku", 1, 1);
    assert_byte_slice(cell_sku, CSV_FIXTURE, "data.csv", "sku");

    let cell_product = find_element(&defs, "data.csv", "cell", "product");
    assert_span(cell_product, "data.csv", "cell:product", 1, 1);
    assert_byte_slice(cell_product, CSV_FIXTURE, "data.csv", "product");

    let cell_notes = find_element(&defs, "data.csv", "cell", "notes");
    assert_span(cell_notes, "data.csv", "cell:notes", 1, 1);
    assert_byte_slice(cell_notes, CSV_FIXTURE, "data.csv", "notes");

    // Record A-1: quoted field with a comma inside — the record span covers
    // the WHOLE physical line, quotes included, and the cell name is the
    // first field's raw text.
    let a1 = find_element(&defs, "data.csv", "record", "A-1");
    assert_span(a1, "data.csv", "record:A-1", 2, 2);
    let a1_slice = &CSV_FIXTURE[a1.byte_start.unwrap() as usize..a1.byte_end.unwrap() as usize];
    assert_eq!(
        a1_slice, "A-1,Widget,\"round, blue\"",
        "record region = the exact source line (comma inside quotes kept)"
    );

    // Record A-2: embedded newline in the quoted field → the record spans
    // lines 3-4 and its byte region reproduces BOTH lines exactly.
    let a2 = find_element(&defs, "data.csv", "record", "A-2");
    assert_span(a2, "data.csv", "record:A-2", 3, 4);
    let a2_slice = &CSV_FIXTURE[a2.byte_start.unwrap() as usize..a2.byte_end.unwrap() as usize];
    assert_eq!(
        a2_slice, "A-2,Gadget,\"sells\nwell, sometimes\"",
        "record region covers the embedded newline record exactly"
    );

    // Record A-3: plain record.
    let a3 = find_element(&defs, "data.csv", "record", "A-3");
    assert_span(a3, "data.csv", "record:A-3", 5, 5);
    assert_byte_slice(a3, CSV_FIXTURE, "data.csv", "A-3");
}

// TSV is the same scanner with `\t` as the delimiter byte — one fixture pin.
const TSV_FIXTURE: &str = "id\tname\n1\tada\n";

#[test]
fn tsv_records_use_the_tab_delimiter() {
    let defs = extract_elements("data.tsv", TSV_FIXTURE, Language::Tsv);

    let sequence: Vec<(String, String)> = defs
        .iter()
        .map(|d| (d.kind.clone(), d.name.clone()))
        .collect();
    let expected: Vec<(String, String)> = [
        ("record", "id"),
        ("cell", "id"),
        ("cell", "name"),
        ("record", "1"),
    ]
    .iter()
    .map(|(k, n)| (k.to_string(), n.to_string()))
    .collect();
    assert_eq!(
        sequence, expected,
        "element-extraction-v1 [data.tsv]: expected exact record/cell sequence"
    );

    let header = find_element(&defs, "data.tsv", "record", "id");
    assert_span(header, "data.tsv", "record:id", 1, 1);
    let header_slice =
        &TSV_FIXTURE[header.byte_start.unwrap() as usize..header.byte_end.unwrap() as usize];
    assert_eq!(header_slice, "id\tname");
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
        ("pinned.tex", LATEX_FIXTURE, Language::Latex, 6),
        ("server.log", LOG_FIXTURE, Language::Log, 6),
        ("notes.txt", TEXT_FIXTURE, Language::Text, 6),
        ("README.md", MARKDOWN_FIXTURE, Language::Markdown, 7),
        ("data.csv", CSV_FIXTURE, Language::Csv, 7),
        ("data.tsv", TSV_FIXTURE, Language::Tsv, 4),
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
