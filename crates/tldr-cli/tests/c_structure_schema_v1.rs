//! c-structure-functions-schema-v1 (v0.4.2 bug-B1 / VAL-C-STRUCT,
//! updated for structure-functions-projection-v1 / v0.4.2 M-006)
//!
//! ## History
//!
//! 1. v0.4.2 bug-B1 (VAL-C-STRUCT): the original audit reported that
//!    `tldr structure` for C had `.files[].functions == []` while other
//!    languages populated it. Investigation (W-I, commit 6f4be31)
//!    showed the field was ABSENT from JSON for every language per
//!    `schema-cleanup-v1` BUG-13 (commit 3e9b159) — `Vec<String>`
//!    fields `functions`/`methods` were `#[serde(skip_serializing)]`.
//!    The canonical functions surface was
//!    `files[].definitions[] | select(.kind == "function")`.
//!
//! 2. v0.4.2 M-006 (Phase-22 cross-lang audit, ~9 langs: c, csharp,
//!    elixir, go, java, javascript, lua, luau, ocaml, typescript):
//!    re-evaluated W-I's choice. Downstream tooling/consumers across
//!    9 langs expect `.files[].functions[]` to be present. The
//!    `structure-functions-projection-v1` fix re-introduces the
//!    `functions[]` key — but as a **projection of
//!    `definitions[].filter(kind == "function")`**, not as the legacy
//!    redundant `Vec<String>` array. Each entry has the same shape
//!    as `DefinitionInfo` (name, kind, line_start, line_end,
//!    signature), so consumers reading `.files[].functions[].name`
//!    get the canonical function set without re-filtering
//!    `definitions[]`.
//!
//!    BUG-13's actual invariant — that `functions: [String]` (legacy
//!    bare-string array) must never appear — is preserved: the
//!    projection contains objects, never strings. The `methods:
//!    [String]` legacy field remains `skip_serializing` (canonical
//!    surface for methods is still `method_infos`).
//!
//! ## What this file asserts (post-M-006)
//!
//! - `files[].functions` IS now present in JSON output for C and Rust.
//! - Its entries are objects matching the `DefinitionInfo` shape.
//! - The function-name set still agrees with `tldr extract`'s
//!   `functions[].name`.
//! - The `definitions[].filter(kind=function)` query still returns
//!   the same function set, so the schema is self-consistent.
//!
//! Real-repo gated per no-synthetic-fixtures-v1: each test returns
//! early when its `/tmp/repos/<repo>` corpus is absent.

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

const C_CORPUS_FILE: &str = "/tmp/repos/c-sds/sds.c";
const RUST_CORPUS_DIR: &str = "/tmp/repos/ripgrep";

// ============================================================================
// TEST 1: For C structure JSON, function-kind definitions are populated
//         (the canonical "functions in this file" surface).
// ============================================================================
#[test]
fn c_structure_files_functions_populated() {
    if !Path::new(C_CORPUS_FILE).exists() {
        eprintln!(
            "[skip] c_structure_files_functions_populated: corpus {} not present",
            C_CORPUS_FILE
        );
        return;
    }
    let (rc, out) = run_tldr(&["structure", C_CORPUS_FILE, "--format", "json"]);
    assert_eq!(rc, 0, "structure must succeed; got rc={}", rc);
    let v = parse_json(&out);

    // structure-functions-projection-v1 (M-006): files[].functions
    // is now PRESENT and projects from definitions[].kind == "function".
    // Each entry must be an OBJECT (DefinitionInfo shape), never a bare
    // string — that preserves the original BUG-13 intent.
    let file0 = v
        .pointer("/files/0")
        .unwrap_or_else(|| panic!("structure: missing files[0]; got {v}"));
    let fns = file0
        .get("functions")
        .and_then(|f| f.as_array())
        .unwrap_or_else(|| {
            panic!(
                "M-006 regression: files[0].functions key must be \
                 present (projection from definitions[kind=function]). Got: {file0}"
            )
        });
    assert!(
        !fns.is_empty(),
        "M-006: C structure must populate ≥1 entry in files[0].functions for sds.c"
    );
    for fe in fns {
        assert!(
            fe.is_object(),
            "BUG-13 + M-006: functions[] entry must be an object \
             (DefinitionInfo shape), not a bare string. Got: {fe}"
        );
    }

    // Definitions are populated (≥1 function-kind entry); the schema
    // remains self-consistent — functions[] is a projection of
    // definitions[].filter(kind=="function").
    let defs = file0
        .get("definitions")
        .and_then(|d| d.as_array())
        .unwrap_or_else(|| panic!("structure: files[0].definitions absent or non-array: {file0}"));
    let fn_count = defs
        .iter()
        .filter(|d| d.get("kind").and_then(|k| k.as_str()) == Some("function"))
        .count();
    assert!(
        fn_count > 0,
        "VAL-C-STRUCT: C structure must populate ≥1 \
         function-kind definition for sds.c. Got fn_count=0; defs={defs:?}"
    );
    assert_eq!(
        fns.len(),
        fn_count,
        "M-006: functions[] length ({}) must equal \
         definitions[kind=function] length ({}) — projection identity",
        fns.len(),
        fn_count
    );
}

// ============================================================================
// TEST 2: C structure's function-kind definitions agree (by name set)
//         with the function-kind definitions in the same JSON — i.e. the
//         schema is internally consistent (no name appears only in
//         method_infos or only in definitions).
// ============================================================================
#[test]
fn c_structure_functions_match_definitions() {
    if !Path::new(C_CORPUS_FILE).exists() {
        eprintln!(
            "[skip] c_structure_functions_match_definitions: corpus {} not present",
            C_CORPUS_FILE
        );
        return;
    }
    let (rc, out) = run_tldr(&["structure", C_CORPUS_FILE, "--format", "json"]);
    assert_eq!(rc, 0, "structure must succeed; got rc={}", rc);
    let v = parse_json(&out);

    let defs = v
        .pointer("/files/0/definitions")
        .and_then(|d| d.as_array())
        .unwrap_or_else(|| panic!("structure: files[0].definitions missing; got {v}"));
    let fn_names: Vec<String> = defs
        .iter()
        .filter(|d| d.get("kind").and_then(|k| k.as_str()) == Some("function"))
        .filter_map(|d| {
            d.get("name")
                .and_then(|n| n.as_str())
                .map(|s| s.to_string())
        })
        .collect();

    // Every function-kind entry has a non-empty name and a line_start.
    for d in defs
        .iter()
        .filter(|d| d.get("kind").and_then(|k| k.as_str()) == Some("function"))
    {
        let name = d
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or_else(|| panic!("function definition missing name: {d}"));
        assert!(
            !name.is_empty(),
            "C function definition has empty name: {d}"
        );
        let line = d
            .get("line_start")
            .and_then(|n| n.as_u64())
            .unwrap_or_else(|| panic!("function definition missing line_start: {d}"));
        assert!(
            line > 0,
            "C function definition has line_start=0: {d}"
        );
    }

    // C has no methods (no classes), so method_infos must be empty
    // for sds.c — the function names live ONLY in definitions[].
    let methods = v
        .pointer("/files/0/method_infos")
        .and_then(|m| m.as_array())
        .unwrap_or_else(|| panic!("structure: files[0].method_infos missing; got {v}"));
    assert!(
        methods.is_empty(),
        "C file should emit empty method_infos (no classes); got {methods:?}"
    );

    assert!(
        !fn_names.is_empty(),
        "VAL-C-STRUCT: extracted function names is empty for sds.c"
    );
}

// ============================================================================
// TEST 3: The function names emitted under structure.files[0].definitions
//         (kind="function") match the function names emitted by
//         `tldr extract` on the same C file — i.e. the "parity with
//         extract" property the audit asked for, achieved via the
//         canonical schema.
// ============================================================================
#[test]
fn c_structure_functions_match_extract() {
    if !Path::new(C_CORPUS_FILE).exists() {
        eprintln!(
            "[skip] c_structure_functions_match_extract: corpus {} not present",
            C_CORPUS_FILE
        );
        return;
    }

    // structure side: extract function names from definitions[]
    let (rc1, s_out) = run_tldr(&["structure", C_CORPUS_FILE, "--format", "json"]);
    assert_eq!(rc1, 0, "structure rc={}", rc1);
    let sv = parse_json(&s_out);
    let s_defs = sv
        .pointer("/files/0/definitions")
        .and_then(|d| d.as_array())
        .unwrap_or_else(|| panic!("structure: files[0].definitions missing"));
    let mut s_names: Vec<String> = s_defs
        .iter()
        .filter(|d| d.get("kind").and_then(|k| k.as_str()) == Some("function"))
        .filter_map(|d| {
            d.get("name")
                .and_then(|n| n.as_str())
                .map(|s| s.to_string())
        })
        .collect();
    s_names.sort();

    // extract side: top-level functions[] names
    let (rc2, e_out) = run_tldr(&["extract", C_CORPUS_FILE, "--format", "json"]);
    assert_eq!(rc2, 0, "extract rc={}", rc2);
    let ev = parse_json(&e_out);
    let e_fns = ev
        .get("functions")
        .and_then(|f| f.as_array())
        .unwrap_or_else(|| panic!("extract: functions[] missing; got {ev}"));
    let mut e_names: Vec<String> = e_fns
        .iter()
        .filter_map(|f| {
            f.get("name")
                .and_then(|n| n.as_str())
                .map(|s| s.to_string())
        })
        .collect();
    e_names.sort();

    assert!(
        !e_names.is_empty(),
        "extract: 0 function names extracted from sds.c (corpus issue?)"
    );

    // The two name sets must agree. This is the parity guarantee the
    // VAL-C-STRUCT audit was asking for — achieved via the canonical
    // `definitions[].kind == "function"` schema (BUG-13), not via
    // re-introducing the deprecated `files[].functions` string array.
    assert_eq!(
        s_names, e_names,
        "VAL-C-STRUCT parity: structure-derived function names \
         (from definitions[].kind==\"function\") must equal \
         extract.functions[].name. structure={s_names:?}, \
         extract={e_names:?}"
    );
}

// ============================================================================
// TEST 4 (post-M-006): Rust structure on ripgrep follows the
//                       structure-functions-projection-v1 schema —
//                       `files[].functions` IS present in JSON output
//                       (as a projection of definitions[kind=function])
//                       and `definitions[]` is populated with the same
//                       function set. The schema is uniform across
//                       languages.
// ============================================================================
#[test]
fn rust_structure_files_functions_still_populated() {
    if !Path::new(RUST_CORPUS_DIR).exists() {
        eprintln!(
            "[skip] rust_structure_files_functions_still_populated: corpus {} not present",
            RUST_CORPUS_DIR
        );
        return;
    }
    let (rc, out) = run_tldr(&[
        "structure",
        RUST_CORPUS_DIR,
        "--format",
        "json",
        "--lang",
        "rust",
    ]);
    assert_eq!(rc, 0, "structure must succeed; got rc={}", rc);
    let v = parse_json(&out);
    let files = v
        .get("files")
        .and_then(|f| f.as_array())
        .unwrap_or_else(|| panic!("structure: files[] missing; got {v}"));
    assert!(!files.is_empty(), "ripgrep has rust source files");

    // For at least one rust file (the one with the most function-kind
    // definitions), confirm post-M-006 schema:
    //   - `functions` key PRESENT (M-006 projection)
    //   - functions[] count == definitions[kind=function] count
    //   - functions[] entries are objects, not strings (BUG-13 spirit)
    //   - `definitions[]` populated with ≥1 kind=="function" entry
    //
    // We pick the file with the most function-kind defs because some
    // small ripgrep modules may be empty re-exports.
    let mut best_fn_count = 0usize;
    let mut best_file: Option<&serde_json::Value> = None;
    for f in files {
        if let Some(defs) = f.get("definitions").and_then(|d| d.as_array()) {
            let n = defs
                .iter()
                .filter(|d| d.get("kind").and_then(|k| k.as_str()) == Some("function"))
                .count();
            if n > best_fn_count {
                best_fn_count = n;
                best_file = Some(f);
            }
        }
    }
    let best_file =
        best_file.unwrap_or_else(|| panic!("no rust file with kind=function defs in ripgrep"));

    let fns = best_file
        .get("functions")
        .and_then(|f| f.as_array())
        .unwrap_or_else(|| {
            panic!(
                "M-006 regression (rust): files[].functions must be \
                 present. Got: {best_file}"
            )
        });
    for fe in fns {
        assert!(
            fe.is_object(),
            "BUG-13 + M-006 (rust): functions[] entry must be an \
             object (DefinitionInfo shape), not a bare string. Got: {fe}"
        );
    }
    assert_eq!(
        fns.len(),
        best_fn_count,
        "M-006 (rust): functions[] length ({}) must equal \
         definitions[kind=function] length ({}) — projection identity",
        fns.len(),
        best_fn_count
    );
    assert!(
        best_fn_count >= 1,
        "rust structure on ripgrep: ≥1 function-kind definition \
         expected; got {best_fn_count}. file: {best_file}"
    );
}
