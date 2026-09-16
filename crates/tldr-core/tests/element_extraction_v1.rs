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
//!
//! Every element pins:
//! 1. EXACT `kind` / `name` / `line_start` / `line_end` (1-indexed), and
//! 2. byte spans present & consistent: `byte_start < byte_end` and
//!    `source[byte_start..byte_end]` starts with the element's first token.
//!
//! Code languages keep `byte_start`/`byte_end` = `None` for now (populating
//! them is a later batch); XML/HTML/CSS keep the empty-definitions baseline
//! (pinned in `symbol_fidelity_v1.rs`) until their element batch.

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
// Cross-format: the JSON shape consumers see is the plain definitions array
// =============================================================================

#[test]
fn elements_flow_through_the_definitions_array_of_every_format() {
    for (filename, content, language, min_elements) in [
        ("pinned.json", JSON_FIXTURE, Language::Json, 4usize),
        ("pinned.toml", TOML_FIXTURE, Language::Toml, 7),
        ("pinned.yaml", YAML_FIXTURE, Language::Yaml, 6),
        ("deploy.sh", BASH_FIXTURE, Language::Bash, 2),
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
