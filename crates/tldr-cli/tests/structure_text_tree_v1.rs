//! structure-text-tree-v1 — the text-mode Elements section as a node tree.
//!
//! CONTRACT UNDER TEST (markup-node-tree-v1, `crates/tldr-cli/src/output.rs`):
//!
//! - `format_structure_text`'s Elements section indents TWO SPACES per
//!   markup nesting level (`DefinitionInfo::depth`): root-level elements at
//!   the base indent, children one level in, and so on. Depth-less rows
//!   (json/yaml/toml keys, inner-CSS selectors, log entries, …) render at
//!   the base indent exactly as before.
//! - Past [`tldr_cli::output::STRUCTURE_TEXT_ELEMENT_CAP`] entries (200) the
//!   section prints the FIRST 200 rows plus one summary line
//!   `… N more elements (use --max-depth to narrow, --max-results to cap,
//!   -f json for all)`. Under the cap every row renders and there is no
//!   summary line — small files are byte-identical to the pre-cap renderer
//!   (for depth-0/None rows).
//! - The cap is a TEXT-renderer concern only: JSON output is always
//!   complete (the machine contract).

use tldr_cli::output::{format_structure_text, STRUCTURE_TEXT_ELEMENT_CAP};
use tldr_core::types::{CodeStructure, DefinitionInfo, FileStructure};
use tldr_core::Language;

/// Build one markup `element` row with a nesting depth.
fn element(name: &str, depth: u32, line: u32) -> DefinitionInfo {
    DefinitionInfo {
        name: name.to_string(),
        kind: "element".to_string(),
        line_start: line,
        line_end: line,
        definition_line: None,
        byte_start: Some(0),
        byte_end: Some(1),
        signature: String::new(),
        container: None,
        depth: Some(depth),
    }
}

/// Build one depth-less row (`kind`/`name`) — a JSON key, a selector, …
fn depthless(kind: &str, name: &str, line: u32) -> DefinitionInfo {
    DefinitionInfo {
        name: name.to_string(),
        kind: kind.to_string(),
        line_start: line,
        line_end: line,
        definition_line: None,
        byte_start: Some(0),
        byte_end: Some(1),
        signature: String::new(),
        container: None,
        depth: None,
    }
}

fn structure_of(definitions: Vec<DefinitionInfo>) -> CodeStructure {
    CodeStructure {
        root: std::path::PathBuf::from("/proj"),
        language: Some(Language::Html),
        files: vec![FileStructure {
            path: std::path::PathBuf::from("page.html"),
            functions: Vec::new(),
            classes: Vec::new(),
            methods: Vec::new(),
            method_infos: Vec::new(),
            imports: Vec::new(),
            definitions,
        }],
        files_skipped: 0,
        warnings: Vec::new(),
        jsonl_stream: None,
    }
}

/// EXACT indentation snapshot: two spaces per depth level under the shared
/// `    - ` base; the depth-less selector row renders at the base indent in
/// its source-order position.
#[test]
fn elements_render_as_a_two_space_per_level_tree() {
    let report = structure_of(vec![
        element("html", 0, 2),
        element("head", 1, 3),
        element("title", 2, 4),
        depthless("selector", "body", 5),
        element("body#main", 1, 7),
        element("br", 2, 10),
    ]);

    let text = format_structure_text(&report);
    let elements_section = text
        .split("  Elements:\n")
        .nth(1)
        .expect("an Elements section must render")
        .trim_end_matches('\n');
    assert_eq!(
        elements_section,
        "    - element html (L2-L2)
      - element head (L3-L3)
        - element title (L4-L4)
    - selector body (L5-L5)
      - element body#main (L7-L7)
        - element br (L10-L10)",
        "the Elements section must be a two-space-per-level node tree with \
         depth-less rows at the base indent"
    );
}

/// A file under the cap renders EVERY row and NO summary line — the small-
/// file output is unchanged apart from the depth indentation.
#[test]
fn files_under_the_cap_render_every_row_without_a_summary_line() {
    let count = STRUCTURE_TEXT_ELEMENT_CAP - 1;
    let defs: Vec<DefinitionInfo> = (0..count)
        .map(|i| element(&format!("e{i}"), (i % 3) as u32, i as u32 + 1))
        .collect();
    let text = format_structure_text(&structure_of(defs));

    let rendered = text.matches("- element e").count();
    assert_eq!(
        rendered, count,
        "every element below the cap must render (got {rendered}/{count})"
    );
    assert!(
        !text.contains("more elements"),
        "no summary line below the cap: {text}"
    );
}

/// AT the cap + 1: exactly the first 200 rows render, then ONE summary line
/// counting the hidden remainder, pointing at the three knobs.
#[test]
fn oversized_files_print_the_first_cap_rows_plus_one_summary_line() {
    let count = STRUCTURE_TEXT_ELEMENT_CAP + 50;
    let defs: Vec<DefinitionInfo> = (0..count)
        .map(|i| element(&format!("e{i}"), 0, i as u32 + 1))
        .collect();
    let text = format_structure_text(&structure_of(defs));

    let rendered = text.matches("- element e").count();
    assert_eq!(
        rendered,
        STRUCTURE_TEXT_ELEMENT_CAP,
        "exactly the first {cap} rows render, got {rendered}",
        cap = STRUCTURE_TEXT_ELEMENT_CAP
    );
    let summary = format!(
        "    … {} more elements (use --max-depth to narrow, --max-results to cap, \
         -f json for all)\n",
        count - STRUCTURE_TEXT_ELEMENT_CAP
    );
    assert!(
        text.contains(&summary),
        "exactly one summary line counting the hidden rows must follow the cap: {text}"
    );
    // The last hidden row must NOT be present (the cap truncates, it does
    // not compress).
    assert!(
        !text.contains("- element e250\n"),
        "rows beyond the cap must not render at all"
    );
}

/// JSON stays complete (the machine contract) while text caps: the same
/// 250-element structure serializes every definition. (Pinned here through
/// serde — the same property the JSON format path relies on.)
#[test]
fn json_remains_complete_while_text_caps() {
    let count = STRUCTURE_TEXT_ELEMENT_CAP + 50;
    let defs: Vec<DefinitionInfo> = (0..count)
        .map(|i| element(&format!("e{i}"), 0, i as u32 + 1))
        .collect();
    let report = structure_of(defs);

    let json = serde_json::to_string(&report).unwrap();
    let serialized_definitions = json.matches("\"kind\":\"element\"").count();
    assert_eq!(
        serialized_definitions, count,
        "JSON output is never capped — only the text renderer is"
    );
}
