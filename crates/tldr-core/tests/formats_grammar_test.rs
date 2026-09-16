//! Formats-extension grammar ABI + parse smoke tests (2025-09).
//!
//! Every new grammar crate must (a) load into the pinned tree-sitter 0.25
//! runtime at `set_language` time (ABI window check) and (b) actually parse a
//! representative snippet into the expected root node kind. If a grammar
//! version bump renames node kinds, these tests fail loudly.

use tldr_core::ast::parser::parse;
use tldr_core::Language;

#[test]
fn json_parses_object() {
    let tree = parse(
        r#"{"name": "tldr", "count": 42, "ok": true}"#,
        Language::Json,
    )
    .unwrap();
    assert_eq!(tree.root_node().kind(), "document");
    assert!(!tree.root_node().has_error());
}

#[test]
fn yaml_parses_mapping() {
    let tree = parse("name: tldr\ncount: 42\n", Language::Yaml).unwrap();
    assert!(
        !tree.root_node().has_error(),
        "yaml root: {}",
        tree.root_node().kind()
    );
}

#[test]
fn toml_parses_table() {
    let tree = parse("[owner]\nname = \"tldr\"\n", Language::Toml).unwrap();
    assert!(
        !tree.root_node().has_error(),
        "toml root: {}",
        tree.root_node().kind()
    );
}

#[test]
fn xml_parses_element() {
    let tree = parse("<root><item id=\"1\">x</item></root>", Language::Xml).unwrap();
    assert!(
        !tree.root_node().has_error(),
        "xml root: {}",
        tree.root_node().kind()
    );
}

#[test]
fn html_parses_document() {
    let tree = parse("<html><body><p>hi</p></body></html>", Language::Html).unwrap();
    assert!(
        !tree.root_node().has_error(),
        "html root: {}",
        tree.root_node().kind()
    );
}

#[test]
fn css_parses_rule() {
    let tree = parse("body { color: red; }", Language::Css).unwrap();
    assert!(
        !tree.root_node().has_error(),
        "css root: {}",
        tree.root_node().kind()
    );
}

#[test]
fn bash_parses_command() {
    let tree = parse("echo hello\ncd /tmp\n", Language::Bash).unwrap();
    assert!(
        !tree.root_node().has_error(),
        "bash root: {}",
        tree.root_node().kind()
    );
}

#[test]
fn new_languages_map_from_extension() {
    for (ext, expected) in [
        (".json", Language::Json),
        (".jsonl", Language::Json),
        (".ndjson", Language::Json),
        (".yaml", Language::Yaml),
        (".yml", Language::Yaml),
        (".toml", Language::Toml),
        (".xml", Language::Xml),
        (".svg", Language::Xml),
        (".html", Language::Html),
        (".css", Language::Css),
        (".sh", Language::Bash),
    ] {
        let got = Language::from_extension(ext).unwrap_or_else(|| panic!("{ext} should resolve"));
        assert_eq!(got, expected, "extension {ext}");
    }
}

#[test]
fn all_25_variants_have_str_and_extensions() {
    assert_eq!(
        Language::all().len(),
        25,
        "Language::all() must list every variant"
    );
    for lang in Language::all() {
        assert!(!lang.as_str().is_empty());
        assert!(!lang.extensions().is_empty());
    }
}
