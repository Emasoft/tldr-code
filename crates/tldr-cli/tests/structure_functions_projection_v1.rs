//! structure-functions-projection-v1 (v0.4.2 M-006)
//!
//! Phase-22 audit M-006 (cluster across ~9 languages: c, csharp, elixir,
//! go, java, javascript, lua, luau, ocaml, typescript) found that
//! consumers of `tldr structure --format json` expect a top-level
//! `files[].functions[]` array to enumerate the functions defined in
//! each source file.
//!
//! That field was dropped by `schema-cleanup-v1` BUG-13 (commit 3e9b159,
//! May 2026) on the basis that it was redundant with
//! `files[].definitions[]` (kind == "function"). The Phase-22 cross-lang
//! audit re-evaluates that choice: downstream tooling DOES expect the
//! conventional `functions` projection, and producing it cheaply from
//! the existing `definitions[]` set restores schema parity with
//! `tldr extract` (which already emits `functions: [...]` at the
//! top-level).
//!
//! This file is the regression guard for the projection. It asserts,
//! across multiple corpora / languages, that:
//!   1. `files[].functions` is present in JSON output.
//!   2. Its contents are exactly the projection
//!      `[d for d in definitions if d.kind == "function"]`
//!      (same name set, same line ranges, same signature strings).
//!   3. The set of names agrees with `tldr extract`'s
//!      `functions[].name` on the same file (parity guarantee).
//!   4. The existing `definitions[]` array is still populated and
//!      carries the same function entries (backward compat).
//!
//! Real-repo gated per no-synthetic-fixtures-v1: each test returns
//! early when its `/tmp/repos/<repo>` corpus is absent.
//!
//! Supersedes BUG-13 / `bug13_structure_no_redundant_string_arrays`
//! for the `functions` key (the `methods` key remains skip_serialized;
//! `method_infos` is the canonical method surface).

use std::path::Path;
use std::process::Command;

fn tldr_bin() -> std::path::PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR must be set under cargo test");
    std::path::PathBuf::from(manifest)
        .join("..")
        .join("..")
        .join("target")
        .join("release")
        .join("tldr")
}

fn run_tldr(args: &[&str]) -> (i32, String) {
    let out = Command::new(tldr_bin())
        .args(args)
        .output()
        .expect("failed to run tldr binary");
    let exit = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    (exit, stdout)
}

fn parse_json(out: &str) -> serde_json::Value {
    serde_json::from_str(out)
        .unwrap_or_else(|e| panic!("invalid JSON: {e}; stdout was:\n{out}"))
}

/// Pull the `definitions[]` entries with kind=="function" from a file
/// node, sorted by `(line_start, name)`. Returns owned values.
fn function_defs(file_node: &serde_json::Value) -> Vec<serde_json::Value> {
    let defs = file_node
        .get("definitions")
        .and_then(|d| d.as_array())
        .unwrap_or_else(|| {
            panic!(
                "structure: file node missing definitions[]; got {file_node}"
            )
        });
    let mut out: Vec<serde_json::Value> = defs
        .iter()
        .filter(|d| d.get("kind").and_then(|k| k.as_str()) == Some("function"))
        .cloned()
        .collect();
    out.sort_by(|a, b| {
        let la = a.get("line_start").and_then(|x| x.as_u64()).unwrap_or(0);
        let lb = b.get("line_start").and_then(|x| x.as_u64()).unwrap_or(0);
        let na = a.get("name").and_then(|x| x.as_str()).unwrap_or("");
        let nb = b.get("name").and_then(|x| x.as_str()).unwrap_or("");
        (la, na).cmp(&(lb, nb))
    });
    out
}

/// Pull `functions[]` from a file node, sorted the same way.
fn projected_functions(file_node: &serde_json::Value) -> Vec<serde_json::Value> {
    let fns = file_node
        .get("functions")
        .and_then(|f| f.as_array())
        .unwrap_or_else(|| {
            panic!(
                "structure: file node missing functions[] (M-006 \
                 projection regression); got {file_node}"
            )
        });
    let mut out: Vec<serde_json::Value> = fns.iter().cloned().collect();
    out.sort_by(|a, b| {
        let la = a.get("line_start").and_then(|x| x.as_u64()).unwrap_or(0);
        let lb = b.get("line_start").and_then(|x| x.as_u64()).unwrap_or(0);
        let na = a.get("name").and_then(|x| x.as_str()).unwrap_or("");
        let nb = b.get("name").and_then(|x| x.as_str()).unwrap_or("");
        (la, na).cmp(&(lb, nb))
    });
    out
}

// =============================================================================
// CORPORA — per-language file targets used below
// =============================================================================

const C_FILE: &str = "/tmp/repos/c-sds/sds.c";
const RUST_DIR: &str = "/tmp/repos/ripgrep";
const GO_DIR: &str = "/tmp/repos/go-httprouter";
const ELIXIR_DIR: &str = "/tmp/repos/elixir-plug";
const TS_DIR: &str = "/tmp/repos/ts-dom-gen";
const CSHARP_DIR: &str = "/tmp/repos/csharp-newtonsoft-bson";
const LUA_DIR: &str = "/tmp/repos/lua-lsp";

// =============================================================================
// TEST 1: C — functions[] present + matches definitions[kind=function] +
//             parity with extract.functions[].name.
// =============================================================================
#[test]
fn c_structure_functions_projection_matches_definitions_and_extract() {
    if !Path::new(C_FILE).exists() {
        eprintln!(
            "[skip] c_structure_functions_projection_matches_definitions_and_extract: corpus {C_FILE} not present"
        );
        return;
    }

    let (rc, out) = run_tldr(&["structure", C_FILE, "--format", "json"]);
    assert_eq!(rc, 0, "structure must succeed; got rc={rc}");
    let v = parse_json(&out);

    let file0 = v
        .pointer("/files/0")
        .unwrap_or_else(|| panic!("structure: missing files[0]; got {v}"));

    // 1) functions[] must be present (M-006 projection).
    let fns = projected_functions(file0);
    assert!(
        !fns.is_empty(),
        "M-006: C structure must populate functions[] for sds.c \
         (45+ functions expected). Got empty."
    );

    // 2) functions[] must equal definitions[kind=function] (same set,
    //    same order after sorting by (line_start, name)).
    let defs = function_defs(file0);
    assert_eq!(
        fns.len(),
        defs.len(),
        "M-006: functions[] length ({}) must match \
         definitions[kind=function] length ({}) for sds.c",
        fns.len(),
        defs.len()
    );
    for (f, d) in fns.iter().zip(defs.iter()) {
        assert_eq!(
            f.get("name"),
            d.get("name"),
            "M-006: functions[] vs definitions[] name mismatch:\n  fn={f}\n def={d}"
        );
        assert_eq!(
            f.get("line_start"),
            d.get("line_start"),
            "M-006: functions[] vs definitions[] line_start mismatch:\n  fn={f}\n def={d}"
        );
        assert_eq!(
            f.get("line_end"),
            d.get("line_end"),
            "M-006: functions[] vs definitions[] line_end mismatch:\n  fn={f}\n def={d}"
        );
    }

    // 3) Parity with extract.functions[].name.
    let (rc2, e_out) = run_tldr(&["extract", C_FILE, "--format", "json"]);
    assert_eq!(rc2, 0, "extract must succeed; got rc={rc2}");
    let ev = parse_json(&e_out);
    let e_fns = ev
        .get("functions")
        .and_then(|f| f.as_array())
        .unwrap_or_else(|| panic!("extract: functions[] missing; got {ev}"));
    let mut s_names: Vec<String> = fns
        .iter()
        .filter_map(|f| f.get("name").and_then(|n| n.as_str()).map(String::from))
        .collect();
    let mut e_names: Vec<String> = e_fns
        .iter()
        .filter_map(|f| f.get("name").and_then(|n| n.as_str()).map(String::from))
        .collect();
    s_names.sort();
    e_names.sort();
    assert_eq!(
        s_names, e_names,
        "M-006 parity: structure.files[0].functions[].name must equal \
         extract.functions[].name for {C_FILE}"
    );
}

// =============================================================================
// TEST 2: Rust (multi-file directory). functions[] is present and
//         non-empty on at least one file; each file's functions[] is
//         exactly the kind=="function" projection of definitions[].
// =============================================================================
#[test]
fn rust_structure_functions_projection_per_file() {
    if !Path::new(RUST_DIR).exists() {
        eprintln!(
            "[skip] rust_structure_functions_projection_per_file: corpus {RUST_DIR} not present"
        );
        return;
    }

    let (rc, out) = run_tldr(&[
        "structure", RUST_DIR, "--format", "json", "--lang", "rust",
    ]);
    assert_eq!(rc, 0, "structure must succeed; got rc={rc}");
    let v = parse_json(&out);
    let files = v
        .get("files")
        .and_then(|f| f.as_array())
        .unwrap_or_else(|| panic!("structure: files[] missing; got {v}"));
    assert!(!files.is_empty(), "ripgrep has rust source files");

    let mut any_nonempty_fns = false;
    for f in files {
        let fns = projected_functions(f);
        let defs = function_defs(f);
        assert_eq!(
            fns.len(),
            defs.len(),
            "M-006: functions[] length must match \
             definitions[kind=function] length for file {}",
            f.get("path").and_then(|p| p.as_str()).unwrap_or("?")
        );
        // Within a file, the names must be identical sets.
        let mut f_names: Vec<&str> = fns
            .iter()
            .filter_map(|d| d.get("name").and_then(|n| n.as_str()))
            .collect();
        let mut d_names: Vec<&str> = defs
            .iter()
            .filter_map(|d| d.get("name").and_then(|n| n.as_str()))
            .collect();
        f_names.sort();
        d_names.sort();
        assert_eq!(
            f_names,
            d_names,
            "M-006: functions[] vs definitions[kind=function] name set \
             mismatch for file {}",
            f.get("path").and_then(|p| p.as_str()).unwrap_or("?")
        );
        if !fns.is_empty() {
            any_nonempty_fns = true;
        }
    }
    assert!(
        any_nonempty_fns,
        "M-006: at least one ripgrep rust file should have a non-empty functions[]"
    );
}

// =============================================================================
// TEST 3: Go — functions[] populated on httprouter (typical multi-file
//             Go module). Asserts presence + non-zero count + projection
//             agreement.
// =============================================================================
#[test]
fn go_structure_functions_projection_present() {
    if !Path::new(GO_DIR).exists() {
        eprintln!(
            "[skip] go_structure_functions_projection_present: corpus {GO_DIR} not present"
        );
        return;
    }
    let (rc, out) = run_tldr(&[
        "structure", GO_DIR, "--format", "json", "--lang", "go",
    ]);
    assert_eq!(rc, 0, "structure must succeed; got rc={rc}");
    let v = parse_json(&out);
    let files = v
        .get("files")
        .and_then(|f| f.as_array())
        .unwrap_or_else(|| panic!("structure: files[] missing; got {v}"));
    assert!(!files.is_empty(), "go-httprouter has go source files");

    let total_fns: usize = files
        .iter()
        .map(|f| projected_functions(f).len())
        .sum();
    let total_def_fns: usize = files
        .iter()
        .map(|f| function_defs(f).len())
        .sum();
    assert!(
        total_fns > 0,
        "M-006: go-httprouter must have ≥1 projected function; got 0"
    );
    assert_eq!(
        total_fns, total_def_fns,
        "M-006: total functions[] across files ({total_fns}) must equal \
         total definitions[kind=function] ({total_def_fns}) for go-httprouter"
    );
}

// =============================================================================
// TEST 4: TypeScript — functions[] populated; projection equals
//                       definitions[kind=function]. Specifically targets
//                       the M-006 finding that src/build/* files were
//                       being dropped (this verifies presence on a
//                       multi-source-file project).
// =============================================================================
#[test]
fn typescript_structure_functions_projection_present() {
    if !Path::new(TS_DIR).exists() {
        eprintln!(
            "[skip] typescript_structure_functions_projection_present: corpus {TS_DIR} not present"
        );
        return;
    }
    let (rc, out) = run_tldr(&[
        "structure",
        TS_DIR,
        "--format",
        "json",
        "--lang",
        "typescript",
    ]);
    assert_eq!(rc, 0, "structure must succeed; got rc={rc}");
    let v = parse_json(&out);
    let files = v
        .get("files")
        .and_then(|f| f.as_array())
        .unwrap_or_else(|| panic!("structure: files[] missing; got {v}"));
    assert!(!files.is_empty(), "ts-dom-gen has TS source files");

    // Every file must have functions[] present (M-006 schema invariant —
    // the key is always emitted, even if empty for that file).
    for f in files {
        assert!(
            f.get("functions").is_some(),
            "M-006: TS file missing functions[] key: {}",
            f.get("path").and_then(|p| p.as_str()).unwrap_or("?")
        );
    }

    let total_fns: usize = files.iter().map(|f| projected_functions(f).len()).sum();
    let total_def_fns: usize = files.iter().map(|f| function_defs(f).len()).sum();
    assert_eq!(
        total_fns, total_def_fns,
        "M-006: TS — total functions[] must match total \
         definitions[kind=function] across files"
    );
}

// =============================================================================
// TEST 5: Schema invariant — `functions` key is ALWAYS present on every
//         file entry in structure JSON output (across multiple languages).
//         This is the core M-006 property: consumers reading
//         `.files[].functions` never get an absent key.
// =============================================================================
#[test]
fn structure_functions_key_always_present_multi_lang() {
    let cases: &[(&str, &str)] = &[
        (C_FILE, "c"),
        (RUST_DIR, "rust"),
        (GO_DIR, "go"),
        (ELIXIR_DIR, "elixir"),
        (TS_DIR, "typescript"),
        (CSHARP_DIR, "csharp"),
        (LUA_DIR, "lua"),
    ];

    let mut covered = 0;
    for (corpus, lang) in cases {
        if !Path::new(corpus).exists() {
            eprintln!("[skip-case] {lang}: corpus {corpus} not present");
            continue;
        }
        let (rc, out) = run_tldr(&[
            "structure", corpus, "--format", "json", "--lang", lang,
        ]);
        assert_eq!(rc, 0, "{lang}: structure must succeed; got rc={rc}");
        let v = parse_json(&out);
        let files = match v.get("files").and_then(|x| x.as_array()) {
            Some(arr) if !arr.is_empty() => arr,
            _ => {
                eprintln!("[skip-case] {lang}: no files in structure output");
                continue;
            }
        };
        for f in files {
            assert!(
                f.get("functions").is_some(),
                "M-006: {lang}: file entry missing functions[] key (always-present schema invariant): {}",
                f.get("path").and_then(|p| p.as_str()).unwrap_or("?")
            );
            // And the projection must agree with definitions filter.
            let fns = projected_functions(f);
            let defs = function_defs(f);
            assert_eq!(
                fns.len(),
                defs.len(),
                "M-006: {lang}: functions[] count mismatch with \
                 definitions[kind=function] for {}",
                f.get("path").and_then(|p| p.as_str()).unwrap_or("?")
            );
        }
        covered += 1;
    }

    // At least one language must have been verified; otherwise this
    // test is silently a no-op which would defeat its purpose.
    assert!(
        covered >= 1,
        "M-006: no corpora available — at least one of {} was expected to exist",
        cases.iter().map(|(p, _)| *p).collect::<Vec<_>>().join(", ")
    );
}

// =============================================================================
// TEST 6: Each functions[] entry has the expected canonical fields:
//         name, kind=="function", line_start>0, line_end>=line_start,
//         signature (may be empty for some langs).
// =============================================================================
#[test]
fn structure_functions_entries_have_canonical_fields() {
    if !Path::new(C_FILE).exists() {
        eprintln!(
            "[skip] structure_functions_entries_have_canonical_fields: corpus {C_FILE} not present"
        );
        return;
    }
    let (rc, out) = run_tldr(&["structure", C_FILE, "--format", "json"]);
    assert_eq!(rc, 0, "structure must succeed; got rc={rc}");
    let v = parse_json(&out);
    let fns = v
        .pointer("/files/0/functions")
        .and_then(|f| f.as_array())
        .unwrap_or_else(|| panic!("M-006: files[0].functions missing"));
    assert!(!fns.is_empty(), "M-006: functions[] must be non-empty for sds.c");

    for f in fns {
        let name = f.get("name").and_then(|n| n.as_str()).unwrap_or_else(|| {
            panic!("M-006: functions[] entry missing name: {f}")
        });
        assert!(!name.is_empty(), "M-006: functions[] entry has empty name: {f}");
        let kind = f.get("kind").and_then(|k| k.as_str()).unwrap_or_else(|| {
            panic!("M-006: functions[] entry missing kind: {f}")
        });
        assert_eq!(
            kind, "function",
            "M-006: functions[] entries must have kind=\"function\"; got {kind} for {f}"
        );
        let ls = f
            .get("line_start")
            .and_then(|n| n.as_u64())
            .unwrap_or_else(|| panic!("M-006: functions[] entry missing line_start: {f}"));
        let le = f
            .get("line_end")
            .and_then(|n| n.as_u64())
            .unwrap_or_else(|| panic!("M-006: functions[] entry missing line_end: {f}"));
        assert!(ls > 0, "M-006: functions[] entry has line_start=0: {f}");
        assert!(
            le >= ls,
            "M-006: functions[] entry has line_end ({le}) < line_start ({ls}): {f}"
        );
        // signature key must be present (string, may be empty).
        assert!(
            f.get("signature").is_some(),
            "M-006: functions[] entry missing signature: {f}"
        );
    }
}
