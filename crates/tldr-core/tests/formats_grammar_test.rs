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
fn latex_parses_document_with_sections_and_environments() {
    // Root kind + section/environment node kinds from the latex grammar
    // (codebook-tree-sitter-latex 0.6.1, republished latex-lsp grammar). If a
    // grammar bump renames these kinds, this fails loudly — the element
    // walker in ast::elements keys on exactly these names.
    let src = "\\documentclass{article}\n\
               \\begin{document}\n\
               \\section{Intro}\n\
               text\n\
               \\subsection{Details}\n\
               \\begin{equation}\n\
               E = mc^2\n\
               \\end{equation}\n\
               \\end{document}\n";
    let tree = parse(src, Language::Latex).unwrap();
    assert_eq!(tree.root_node().kind(), "source_file");
    assert!(
        !tree.root_node().has_error(),
        "latex root: {}",
        tree.root_node().kind()
    );
    for kind in [
        "generic_environment",
        "section",
        "subsection",
        "math_environment",
    ] {
        assert!(
            tree_contains_kind(tree.root_node(), kind),
            "latex tree must contain a `{kind}` node"
        );
    }
}

#[test]
fn markdown_parses_document_with_headings_code_blocks_and_tables() {
    // Root kind + node kinds from the tree-sitter-md 0.5.3 BLOCK grammar
    // (tree_sitter_md::LANGUAGE — the crate's block/inline split is
    // documented at ParserPool and ast::elements::walk_markdown). If a
    // grammar bump renames these kinds, this fails loudly — the element
    // walker in ast::elements keys on exactly these names.
    let src = "# Title\n\nSome prose.\n\n## Sub\n\n```rust\nfn main() {}\n```\n\n| A | B |\n| - | - |\n| 1 | 2 |\n\n    indented code\n";
    let tree = parse(src, Language::Markdown).unwrap();
    assert_eq!(tree.root_node().kind(), "document");
    assert!(
        !tree.root_node().has_error(),
        "markdown root: {}",
        tree.root_node().kind()
    );
    for kind in [
        "section",
        "atx_heading",
        "fenced_code_block",
        "info_string",
        "language",
        "pipe_table",
        "indented_code_block",
    ] {
        assert!(
            tree_contains_kind(tree.root_node(), kind),
            "markdown tree must contain a `{kind}` node"
        );
    }
}

#[test]
fn markdown_setext_heading_and_block_grammar_only() {
    // Setext headings get a dedicated node whose `heading_content` field is
    // the paragraph (the underline is a sibling child). Also pins the
    // block-grammar-only decision: inline emphasis is NOT parsed into
    // emphasis nodes — the ATX heading's `inline` child keeps the raw text
    // (the crate's INLINE_LANGUAGE is deliberately not wired; see
    // ParserPool).
    let src = "Setext Title\n============\n\n# The *Fast* Method\n";
    let tree = parse(src, Language::Markdown).unwrap();
    assert!(!tree.root_node().has_error());
    assert!(tree_contains_kind(tree.root_node(), "setext_heading"));
    assert!(tree_contains_kind(tree.root_node(), "setext_h1_underline"));
    assert!(
        !tree_contains_kind(tree.root_node(), "emphasis"),
        "inline spans must stay unparsed under the BLOCK grammar"
    );
}

fn tree_contains_kind(node: tree_sitter::Node, kind: &str) -> bool {
    if node.kind() == kind {
        return true;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if tree_contains_kind(child, kind) {
            return true;
        }
    }
    false
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
        (".tex", Language::Latex),
        (".sty", Language::Latex),
        (".cls", Language::Latex),
        (".log", Language::Log),
        (".md", Language::Markdown),
        (".markdown", Language::Markdown),
        (".txt", Language::Text),
        (".text", Language::Text),
        (".csv", Language::Csv),
        (".tsv", Language::Tsv),
    ] {
        let got = Language::from_extension(ext).unwrap_or_else(|| panic!("{ext} should resolve"));
        assert_eq!(got, expected, "extension {ext}");
    }
    // Log batch: `.log` detection also works through `from_path` (the path
    // `tldr structure`/`tldr logs` resolve through). NO parse smoke test is
    // possible for Log — there is no tree-sitter grammar — and that absence
    // is itself pinned: parsing log source must stay UnsupportedLanguage.
    assert_eq!(
        Language::from_path(std::path::Path::new("/var/log/app.log")),
        Some(Language::Log)
    );
    assert!(
        tldr_core::ast::parser::parse("some log line", Language::Log).is_err(),
        "logs have no tree-sitter grammar — direct parse must fail"
    );
    // Plain-text batch: `.txt`/`.text` resolve through `from_path` too (the
    // path `tldr structure notes.txt` takes). NO parse smoke test is possible
    // for Text — plain text has NO SYNTAX, so no grammar can exist — and
    // that absence is itself pinned: parsing prose must stay
    // UnsupportedLanguage (the Log no-grammar precedent).
    assert_eq!(
        Language::from_path(std::path::Path::new("docs/notes.txt")),
        Some(Language::Text)
    );
    assert_eq!(
        Language::from_path(std::path::Path::new("docs/notes.text")),
        Some(Language::Text)
    );
    assert!(
        tldr_core::ast::parser::parse("some prose line", Language::Text).is_err(),
        "plain text has no tree-sitter grammar — direct parse must fail"
    );
    // Markdown batch: `.md` also resolves through `from_path` — this is the
    // path `tldr structure README.md` resolves through (the mislabel fix:
    // before this batch `.md` returned None and single-file structure runs
    // fell back to directory autodetect).
    assert_eq!(
        Language::from_path(std::path::Path::new("docs/README.md")),
        Some(Language::Markdown)
    );
    // CSV/TSV batch: `.csv`/`.tsv` resolve through `from_path` too (the path
    // `tldr structure data.csv` takes). NO parse smoke test is possible for
    // Csv/Tsv — the only CSV grammar crate on crates.io (tree-sitter-csv
    // 1.2.0) is unbuildable (cc ~1.0.82 build-dep semver-conflicts with ts
    // 0.25's cc ^1.2.10) and its ts-0.20-era exports ship no bridge
    // LanguageFns (root Cargo.toml audit note) — so parsing data files must
    // stay UnsupportedLanguage (the Log/Text no-grammar precedent). The
    // native RFC 4180 scanner in `ast::csvscan` is the only consumer, pinned
    // by element_extraction_v1/symbol_fidelity_v1.
    assert_eq!(
        Language::from_path(std::path::Path::new("exports/data.csv")),
        Some(Language::Csv)
    );
    assert_eq!(
        Language::from_path(std::path::Path::new("exports/data.tsv")),
        Some(Language::Tsv)
    );
    assert!(
        tldr_core::ast::parser::parse("a,b\n1,2\n", Language::Csv).is_err(),
        "csv has no tree-sitter grammar — direct parse must fail"
    );
    assert!(
        tldr_core::ast::parser::parse("a\tb\n1\t2\n", Language::Tsv).is_err(),
        "tsv has no tree-sitter grammar — direct parse must fail"
    );
}

#[test]
fn all_31_variants_have_str_and_extensions() {
    assert_eq!(
        Language::all().len(),
        31,
        "Language::all() must list every variant"
    );
    for lang in Language::all() {
        assert!(!lang.as_str().is_empty());
        assert!(!lang.extensions().is_empty());
    }
}
