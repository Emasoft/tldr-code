//! yaml full-fidelity e2e — 40,000-line single document through the REAL
//! grammar (V-YAML, 2026-09).
//!
//! # Why this pin exists
//!
//! Upstream `tree-sitter-yaml` 0.7.0's external scanner tracked the source
//! row in `int16_t` and overflowed at row 32768: any single document longer
//! than 32,768 lines aborted into a root `ERROR` node. tldr-code shipped two
//! workarounds around that defect — the `yaml-chunk-v1` document splitter and
//! the `yaml-native-outline-v1` column-0 key scanner (which deliberately
//! excluded nested keys: "nested keys must not emit") — both DELETED now.
//!
//! The grammar is vendored at `vendor/tree-sitter-yaml` with a 31-line int32
//! patch (upstream issue #49: https://github.com/tree-sitter-grammars/tree-
//! sitter-yaml/issues/49 — still open; no fixed fork on crates.io), so yaml
//! parses like every other format: ONE whole-file parse, any size up to the
//! tree-sitter u32 ceiling.
//!
//! # What full fidelity means here (the assertions)
//!
//! A 40,200-line single document (un-splittable: no `---` markers) extracts
//! through the public `get_code_structure` entry point with:
//!
//! 1. **no warnings, nothing skipped** — the old path warned
//!    "single document exceeds the grammar's 32768-line limit" and swapped in
//!    a native outline;
//! 2. **definitions include NESTED keys** — every `block_mapping_pair` at any
//!    depth emits (`unit-N` → `inner` → `deep`/`deeper` → `leaf`), the
//!    JSON/TOML walker convention, where the native outline emitted only
//!    column-0 keys;
//! 3. **the `document-1` element is present** — the native outline emitted no
//!    document element at all;
//! 4. **grammar-exact spans** — single-line nested keys slice back
//!    byte-exactly, nested content sits INSIDE its owning key's line region,
//!    and pre-order (outer key before its nested keys) holds.

use std::fs;
use std::path::Path;
use tempfile::TempDir;
use tldr_core::{get_code_structure, Language};

/// 6 lines per unit, 6,700 units = 40,200 lines — past the old 32,768-row
/// int16 abort with margin.
const UNITS: usize = 6_700;
const LINES_PER_UNIT: usize = 6;
const TOTAL_LINES: usize = UNITS * LINES_PER_UNIT;

/// One unit = a top-level mapping whose value is a nested block:
///
/// ```yaml
/// unit-000000:
///   id: v0
///   inner:
///     deep: v0
///     deeper:
///       leaf: v0
/// ```
///
/// Expected definitions per unit (pre-order): `unit-N`, `id`, `inner`,
/// `deep`, `deeper`, `leaf` — 6 per unit plus the single `document-1`.
fn unit_source(i: usize) -> String {
    format!("unit-{i:06}:\n  id: v{i}\n  inner:\n    deep: v{i}\n    deeper:\n      leaf: v{i}\n")
}

/// 1-indexed first line of unit `i`.
fn unit_line(i: usize) -> usize {
    i * LINES_PER_UNIT + 1
}

fn fixture() -> String {
    (0..UNITS).map(unit_source).collect()
}

/// Pre-order definition names expected for unit `i`.
fn unit_def_names(i: usize) -> [String; 6] {
    [
        format!("unit-{i:06}"),
        format!("id"),
        format!("inner"),
        format!("deep"),
        format!("deeper"),
        format!("leaf"),
    ]
}

fn write_fixture(dir: &Path, source: &str) -> std::path::PathBuf {
    let path = dir.join("giant.yaml");
    fs::write(&path, source).expect("write giant.yaml fixture");
    path
}

#[test]
fn forty_k_line_single_document_extracts_full_fidelity() {
    let source = fixture();
    assert_eq!(source.lines().count(), TOTAL_LINES);

    let dir = TempDir::new().expect("tempdir");
    let path = write_fixture(dir.path(), &source);

    let structure = get_code_structure(&path, Language::Yaml, 0, None)
        .expect("40k-line single-document yaml must extract");

    // (1) one file, nothing skipped, NO warnings — the old path warned about
    // the grammar's line limit and swapped the aborted parse for a native
    // column-0 outline. Silence + full extraction is the new contract.
    assert_eq!(structure.files.len(), 1, "exactly one FileStructure");
    assert_eq!(structure.files_skipped, 0, "nothing skipped");
    assert!(
        structure.warnings.is_empty(),
        "full-fidelity single parse must not warn, got: {:?}",
        structure.warnings
    );

    let defs = &structure.files[0].definitions;

    // (2) + (3) exact count: document-1 plus every mapping pair at every
    // depth (6 per unit — the nested `deep`/`deeper`/`leaf` keys are INCLUDED
    // now; the deleted native outline emitted only the column-0 keys, and no
    // document element at all).
    assert_eq!(
        defs.len(),
        1 + UNITS * 6,
        "document-1 + 6 pre-order definitions per unit (top-level AND nested keys)"
    );

    // document-1: the whole stream, nothing truncated.
    let doc = &defs[0];
    assert_eq!(doc.kind, "document", "defs[0] is the document element");
    assert_eq!(doc.name, "document-1");
    assert_eq!(doc.line_start, 1, "document starts at line 1");
    assert_eq!(
        doc.line_end, TOTAL_LINES as u32,
        "document spans the full 40,200 lines — nothing truncated"
    );
    assert_eq!(doc.byte_start, Some(0));
    assert_eq!(doc.byte_end, Some(source.len() as u64));

    // (4) pre-order + grammar-exact spans, probed at head, stride and last.
    for &i in &[0usize, 1, UNITS / 2, UNITS - 2, UNITS - 1] {
        let base = 1 + i * 6;
        let names = unit_def_names(i);
        for (slot, name) in names.iter().enumerate() {
            let def = &defs[base + slot];
            assert_eq!(def.kind, "key", "unit {i} slot {slot} is a key");
            assert_eq!(def.name, *name, "unit {i} slot {slot} pre-order name");
            let expected_line = unit_line(i) + slot;
            assert_eq!(
                def.line_start, expected_line as u32,
                "unit {i} key `{name}` starts on its own line"
            );
        }

        // The top-level key's region contains the whole nested block: its
        // span covers the unit's 6 lines (key plus value subtree).
        let unit_def = &defs[base];
        assert_eq!(
            unit_def.line_end,
            (unit_line(i) + LINES_PER_UNIT - 1) as u32,
            "unit {i} top-level key spans its whole nested block"
        );
        let unit_bytes =
            &source[unit_def.byte_start.unwrap() as usize..unit_def.byte_end.unwrap() as usize];
        assert!(
            unit_bytes.starts_with(&format!("unit-{i:06}:")),
            "unit {i} top-level key byte region starts at its key"
        );
        assert!(
            unit_bytes.trim_end().ends_with(&format!("leaf: v{i}")),
            "unit {i} top-level key region contains the nested `leaf` line"
        );

        // Nested keys slice back byte-exactly (single-line pairs).
        let deep = &defs[base + 3];
        assert_eq!(
            &source[deep.byte_start.unwrap() as usize..deep.byte_end.unwrap() as usize],
            format!("deep: v{i}"),
            "unit {i} nested `deep` key byte-exact"
        );
        let leaf = &defs[base + 5];
        assert_eq!(
            &source[leaf.byte_start.unwrap() as usize..leaf.byte_end.unwrap() as usize],
            format!("leaf: v{i}"),
            "unit {i} nested `leaf` key byte-exact"
        );
    }

    // (2) again, by NAME across the whole file: every nested key name appears
    // exactly once per unit.
    for name in ["deep", "deeper", "leaf", "inner", "id"] {
        let count = defs.iter().filter(|d| d.name == name).count();
        assert_eq!(count, UNITS, "nested key `{name}` emitted once per unit");
    }
    let top = defs.iter().filter(|d| d.name.starts_with("unit-")).count();
    assert_eq!(top, UNITS, "every top-level unit key emitted");
}
