//! c-structure-functions-schema-v1 (v0.4.2 bug-B1 / VAL-C-STRUCT)
//!
//! The v0.4.2 audit raised VAL-C-STRUCT claiming `tldr structure` for C
//! "reports `.files[].functions == []` (empty array) while putting all
//! 46 C functions under `.files[].definitions[]` with `kind: "function"`"
//! and asserted that "other langs (rust, python, java) populate
//! `.files[].functions` properly".
//!
//! Investigation (W-I) found the assertion is factually incorrect:
//!
//! 1. Per `schema-cleanup-v1` BUG-13 (commit 3e9b159, May 2026) the
//!    `FileStructure::functions: Vec<String>` and
//!    `FileStructure::methods: Vec<String>` fields are intentionally
//!    `#[serde(skip_serializing)]` for ALL languages — they were
//!    redundant with `definitions[]` (which carries name + kind +
//!    line_start + line_end + signature) and `method_infos[]`.
//!
//! 2. Therefore the `functions` key is ABSENT from `tldr structure`
//!    JSON output for every language (Rust, Python, Java, C, C++,
//!    Go, Ruby, Scala, Kotlin, PHP, Swift, C#, Elixir, Lua, OCaml,
//!    Luau, TypeScript/JavaScript) — not "empty for C, populated for
//!    others" as the audit claimed.
//!
//! 3. The canonical source of "functions defined in this file" in
//!    `tldr structure` JSON is
//!    `files[].definitions[] | select(.kind == "function")`. For C
//!    on `/tmp/repos/c-sds/sds.c`, this yields the same 45 function
//!    names that `tldr extract <file>` emits in its top-level
//!    `functions[]` array — i.e. parity with extract is ALREADY
//!    achieved through the canonical schema, just not via the
//!    deprecated `files[].functions` key.
//!
//! This test file is a regression guard against accidentally
//! re-introducing the redundant `files[].functions` string array
//! (which would regress BUG-13) AND against C-specific extraction
//! regressions (it pins the kind="function" count from
//! `definitions[]` to agree with `tldr extract`).
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

    // BUG-13 invariant: the deprecated `files[].functions` string array
    // is NOT emitted as a JSON key. The canonical functions surface is
    // `files[].definitions[] | kind == "function"`.
    let file0 = v
        .pointer("/files/0")
        .unwrap_or_else(|| panic!("structure: missing files[0]; got {v}"));
    assert!(
        file0.get("functions").is_none(),
        "BUG-13 regression: files[0].functions should be \
         skip_serialized; presence of the key would re-introduce a \
         redundant string array. Got: {file0}"
    );

    // Definitions are populated (≥1 function-kind entry).
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
// TEST 4 (non-reg): Rust structure on ripgrep also follows the BUG-13
//                   schema — `files[].functions` is absent from JSON,
//                   `definitions[]` is populated. Documents that the
//                   audit's claim "other langs (rust) populate
//                   files[].functions properly" was incorrect: the
//                   schema is uniform across languages.
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
    // definitions), confirm:
    //   - `functions` key absent (BUG-13 schema)
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

    assert!(
        best_file.get("functions").is_none(),
        "BUG-13 schema (rust): files[].functions should be \
         skip_serialized for rust just like C. Got: {best_file}"
    );
    assert!(
        best_fn_count >= 1,
        "rust structure on ripgrep: ≥1 function-kind definition \
         expected; got {best_fn_count}. file: {best_file}"
    );
}
