//! cl4-cyclomatic-v1 (GH #75, #76) — per-language cyclomatic decision-node
//! arms in `complexity.rs`.
//!
//! `tldr complexity` undercounts branches because its
//! `count_cyclomatic_increment` lacks the per-language decision-node kinds
//! that the *canonical* SonarSource cognitive calculator already handles.
//! The symptom: branchy real-world functions that are riddled with
//! `when`/`match`/`switch`/`if`/`&&`/`||` report `cyclomatic = 1` (the base
//! value) because not a single decision point is credited.
//!
//! Proof the AST is fine: `tldr cognitive` (which walks the SAME tree) gives
//! a non-trivial score for every one of these functions. The bug is purely
//! in the cyclomatic arm-set.
//!
//! Languages and grammars covered here:
//!   - Kotlin (`kotlin-datetime`): `when_expression` / `when_entry` /
//!     `if_expression`.
//!   - C# (`csharp-newtonsoft-bson`): `switch_statement` / `switch_section`
//!     / `foreach_statement` — the C# CFG additionally had no switch/foreach
//!     arm, so the per-case blocks were never emitted.
//!   - OCaml (`ocaml-dune`): `if_expression` / `match_expression` /
//!     `match_case`.
//!   - Scala (`cats-effect`): `if_expression` + `infix_expression` whose
//!     operator is `&&` / `||`.
//!
//! Each test pins a REAL function in a REAL corpus checkout, asserts
//! `cyclomatic > 1`, and asserts the exact value derived from counting the
//! branch nodes in the source. Tests are skipped (with a loud eprintln) only
//! when the corpus is absent, so they never silently pass.

use assert_cmd::Command;
use serde_json::Value;
use std::path::Path;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

/// Run `tldr complexity <file> <function> --format json` and return the
/// parsed cyclomatic value. Panics with full stderr/stdout on any failure.
fn cyclomatic(file: &str, function: &str) -> u64 {
    let output = tldr_cmd()
        .args(["complexity", file, function, "--format", "json"])
        .output()
        .unwrap_or_else(|e| panic!("invoke tldr complexity {file} {function}: {e}"));
    assert!(
        output.status.success(),
        "tldr complexity {file} {function} failed: stderr=\n{}\nstdout=\n{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("tldr complexity stdout not JSON: {e}\n{stdout}"));
    v.get("cyclomatic")
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("no numeric `cyclomatic` field in:\n{stdout}"))
}

/// Skip-guard: returns true (and logs loudly) if the corpus file is missing.
fn missing(file: &str) -> bool {
    if !Path::new(file).exists() {
        eprintln!("SKIP: corpus file not present: {file}");
        return true;
    }
    false
}

// ---------------------------------------------------------------------------
// Kotlin — when_expression / when_entry / if_expression
// ---------------------------------------------------------------------------

/// `Int.monthLength` is a `when (this)` over month numbers:
///   `2 -> if (isLeapYear) 29 else 28`
///   `4, 6, 9, 11 -> 30`
///   `else -> 31`
/// Decision points: when(2 non-`else` entries) + the inner `if`.
/// Cyclomatic = base(1) + when(1) + 2 entries + if(1) = 5 — exactly the
/// number `tldr cognitive --include-cyclomatic` already reports.
#[test]
fn kotlin_when_if_branches_counted() {
    let file =
        "/tmp/tldr_corpora/kotlin-datetime/core/common/src/internal/dateCalculations.kt";
    if missing(file) {
        return;
    }
    let c = cyclomatic(file, "monthLength");
    assert!(
        c > 1,
        "Kotlin monthLength must credit when/when_entry/if branches, got cyclomatic={c}"
    );
    assert_eq!(
        c, 5,
        "Kotlin monthLength: base(1)+when(1)+2 when_entry+if(1) = 5, got {c}"
    );
}

// ---------------------------------------------------------------------------
// C# — switch_statement / switch_section / foreach_statement
// ---------------------------------------------------------------------------

/// `IsPrimitiveToken` is a single `switch (token)` with 8 `case` labels
/// (Integer/Float/String/Boolean/Undefined/Null/Date/Bytes) plus a
/// `default`. Each non-default `switch_section` is a decision point.
/// Cyclomatic = base(1) + 8 cases = 9.
#[test]
fn csharp_switch_sections_counted() {
    let file = "/tmp/tldr_corpora/csharp-newtonsoft-bson/Src/Newtonsoft.Json.Bson/Utilities/JsonTokenUtils.cs";
    if missing(file) {
        return;
    }
    let c = cyclomatic(file, "IsPrimitiveToken");
    assert!(
        c > 1,
        "C# IsPrimitiveToken switch must credit each case, got cyclomatic={c}"
    );
    assert_eq!(
        c, 9,
        "C# IsPrimitiveToken: base(1)+8 non-default switch_section = 9, got {c}"
    );
}

/// `WriteTokenInternal` is a `switch (t.Type)` with 13 non-default cases
/// plus a `default`, and two `foreach` loops inside the Object/Array cases.
/// Cyclomatic = base(1) + 13 cases + 2 foreach = 16.
#[test]
fn csharp_switch_and_foreach_counted() {
    let file = "/tmp/tldr_corpora/csharp-newtonsoft-bson/Src/Newtonsoft.Json.Bson/BsonBinaryWriter.cs";
    if missing(file) {
        return;
    }
    let c = cyclomatic(file, "WriteTokenInternal");
    assert!(
        c > 1,
        "C# WriteTokenInternal switch+foreach must be credited, got cyclomatic={c}"
    );
    assert_eq!(
        c, 16,
        "C# WriteTokenInternal: base(1)+13 cases+2 foreach = 16, got {c}"
    );
}

// ---------------------------------------------------------------------------
// OCaml — if_expression / match_expression / match_case
// ---------------------------------------------------------------------------

/// `encode_action` is a large `match` over the shell-action variant type.
/// `tldr cognitive --include-cyclomatic` already reports 25 for it (the
/// canonical calculator credits the match + every non-wildcard arm). The
/// cyclomatic arm-set must match that exactly.
#[test]
fn ocaml_match_arms_counted() {
    let file = "/tmp/tldr_corpora/ocaml-dune/bin/print_rules.ml";
    if missing(file) {
        return;
    }
    let c = cyclomatic(file, "encode_action");
    assert!(
        c > 1,
        "OCaml encode_action match must credit each arm, got cyclomatic={c}"
    );
    assert_eq!(
        c, 25,
        "OCaml encode_action: must equal the canonical cognitive cyclomatic (25), got {c}"
    );
}

// ---------------------------------------------------------------------------
// Scala — if_expression + infix_expression(&&/||)
// ---------------------------------------------------------------------------

/// `put` has two `if (...)` expressions, a `while` loop, and an `&&` inside
/// the inner `if ((cur ne null) && (cur ne Tombstone))`. Scala parses the
/// `&&` as an `infix_expression` whose `operator` field is `&&` — a node
/// shape that the generic `binary_expression`/`boolean_operator` arm does
/// not recognise. Cyclomatic = base(1) + 2 if + 1 while + 1 `&&` = 5.
#[test]
fn scala_if_and_infix_logical_counted() {
    let file = "/tmp/tldr_corpora/scala-cats-effect/core/shared/src/main/scala/cats/effect/unsafe/ThreadSafeHashtable.scala";
    if missing(file) {
        return;
    }
    let c = cyclomatic(file, "put");
    assert!(
        c > 1,
        "Scala put if/while/&& must be credited, got cyclomatic={c}"
    );
    assert_eq!(
        c, 5,
        "Scala put: base(1)+2 if_expression+1 while+1 `&&` infix = 5, got {c}"
    );
}
