//! cl4r-csharp-cognitive-v1 (v0.5.0 CL-4R residual) — C# cognitive switch
//! arms + has_loops aggregation through switch arms, plus Luau compound
//! assignment implicit-read.
//!
//! CL-4 (cl4-cyclomatic-v1) fixed the *cyclomatic* arm-set so C#
//! `switch_section` / `foreach_statement` are credited. But three sibling
//! gaps remained, each on a DIFFERENT walker that traverses the SAME tree:
//!
//!   1. COGNITIVE walker (`cognitive::CognitiveCalculator`): had no C#
//!      `switch_section` arm and no `foreach_statement` arm, so a 13-arm
//!      switch with two nested `foreach` loops reported `cognitive = 1`
//!      (the SonarSource construct should credit the `switch` +1, each
//!      non-default `switch_section` +1, and each `foreach` +1 plus a
//!      nesting penalty for being inside the switch).
//!
//!   2. has_loops AGGREGATION (CFG `process_csharp_switch`): the per-section
//!      walker only descended into children whose kind ends with
//!      `_statement`. Real C# case bodies are wrapped in a `block` node
//!      (`case X: { ... break; }`), so a `foreach` *inside* that block was
//!      never routed through `process_for_loop` — no LoopHeader / back-edge
//!      was emitted, and `tldr explain` reported `has_loops: false` for a
//!      function that plainly loops.
//!
//!   3. Luau compound assignment (`dfg::process_*`): tree-sitter-luau spells
//!      `total += v` as a distinct `update_statement` node (NOT
//!      `assignment_statement`). The DFG dispatcher had no `update_statement`
//!      arm, so the LHS target's implicit READ (an op-assign reads the prior
//!      value before writing back) was lost. A backward slice of the
//!      accumulator therefore omitted the `+=` line entirely.
//!
//! Each test pins a REAL function in a REAL corpus checkout (or a minimal
//! Luau snippet written to a temp file for the slice case), and skips loudly
//! (never silently passes) when the corpus is absent.

use assert_cmd::Command;
use serde_json::Value;
use std::path::Path;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

/// Skip-guard: returns true (and logs loudly) if the corpus file is missing.
fn missing(file: &str) -> bool {
    if !Path::new(file).exists() {
        eprintln!("SKIP: corpus file not present: {file}");
        return true;
    }
    false
}

const BSON_WRITER: &str =
    "/tmp/tldr_corpora/csharp-newtonsoft-bson/Src/Newtonsoft.Json.Bson/BsonBinaryWriter.cs";

/// Run `tldr cognitive <file> --function <fn> --format json` and return the
/// single function's cognitive score.
fn cognitive(file: &str, function: &str) -> u64 {
    let output = tldr_cmd()
        .args(["cognitive", file, "--function", function, "--format", "json"])
        .output()
        .unwrap_or_else(|e| panic!("invoke tldr cognitive {file} {function}: {e}"));
    assert!(
        output.status.success(),
        "tldr cognitive {file} {function} failed: stderr=\n{}\nstdout=\n{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("tldr cognitive stdout not JSON: {e}\n{stdout}"));
    v.get("functions")
        .and_then(Value::as_array)
        .and_then(|fns| fns.iter().find(|f| f.get("name").and_then(Value::as_str) == Some(function)))
        .and_then(|f| f.get("cognitive"))
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("no cognitive value for {function} in:\n{stdout}"))
}

// ---------------------------------------------------------------------------
// 1. C# cognitive — switch_section arms + nested foreach must be credited.
// ---------------------------------------------------------------------------

/// `WriteTokenInternal` is `switch (t.Type)` with 13 non-default `case`
/// sections plus a `default`, and two `foreach` loops inside the Object/Array
/// case blocks. The cognitive walker must credit the dispatch construct and
/// each case arm, and the nested loops, so the score is comfortably above the
/// degenerate `cognitive = 1` the pre-fix walker produced.
#[test]
fn csharp_switch_foreach_cognitive_counted() {
    if missing(BSON_WRITER) {
        return;
    }
    let c = cognitive(BSON_WRITER, "WriteTokenInternal");
    assert!(
        c > 1,
        "C# WriteTokenInternal switch+foreach must score above the degenerate \
         cognitive=1; the switch dispatch, each case arm, and the two nested \
         foreach loops are all cognitive increments, got {c}"
    );
    // 13 non-default switch_section arms each add +1; the two foreach loops
    // each add +1 base + nesting penalty (they are nested one level inside the
    // switch). That alone is far more than 10.
    assert!(
        c >= 13,
        "C# WriteTokenInternal: 13 case arms + 2 nested foreach should give a \
         cognitive score of at least 13, got {c}"
    );
}

// ---------------------------------------------------------------------------
// 2. has_loops aggregation — a foreach nested in a switch arm must propagate
//    to the top-level `tldr explain` complexity summary.
// ---------------------------------------------------------------------------

/// `tldr explain WriteTokenInternal` must report `has_loops: true` — the
/// function loops via the two `foreach` statements buried inside the
/// `case BsonType.Object:` / `case BsonType.Array:` blocks. The CFG
/// `process_csharp_switch` walker must descend into the `block`-wrapped case
/// body so `process_for_loop` emits the loop structure.
#[test]
fn csharp_foreach_in_switch_sets_has_loops() {
    if missing(BSON_WRITER) {
        return;
    }
    let output = tldr_cmd()
        .args(["explain", BSON_WRITER, "WriteTokenInternal", "--format", "json"])
        .output()
        .expect("invoke tldr explain");
    assert!(
        output.status.success(),
        "tldr explain failed: stderr=\n{}",
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("tldr explain stdout not JSON: {e}\n{stdout}"));
    let has_loops = v
        .get("complexity")
        .and_then(|c| c.get("has_loops"))
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("no complexity.has_loops in:\n{stdout}"));
    assert!(
        has_loops,
        "C# WriteTokenInternal loops via two foreach statements nested in \
         switch arms; has_loops must be true, got false"
    );
}

// ---------------------------------------------------------------------------
// 3. Luau compound assignment — `total += v` (an `update_statement`) is an
//    implicit read of `total`, so a backward slice of the accumulator must
//    include the `+=` line.
// ---------------------------------------------------------------------------

/// tree-sitter-luau parses `acc += v` as an `update_statement` (distinct from
/// `assignment_statement`). The op-assign both READS the prior value of `acc`
/// and writes a new one. A backward slice of `return acc` must therefore
/// include the `acc += v` line — it contributes to the returned value.
#[test]
fn luau_compound_assign_is_implicit_read() {
    let src = "local function tally(items)\n\
               \tlocal acc = 10\n\
               \tfor _, v in items do\n\
               \t\tacc += v\n\
               \tend\n\
               \treturn acc\n\
               end\n";
    let dir = std::env::temp_dir();
    let path = dir.join("cl4r_luau_opassign.luau");
    std::fs::write(&path, src).expect("write temp luau file");
    let path_str = path.to_str().unwrap();

    let output = tldr_cmd()
        .args(["slice", path_str, "tally", "6", "--lang", "luau", "--format", "json"])
        .output()
        .expect("invoke tldr slice");
    assert!(
        output.status.success(),
        "tldr slice failed: stderr=\n{}",
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("tldr slice stdout not JSON: {e}\n{stdout}"));
    let lines: Vec<u64> = v
        .get("lines")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_u64).collect())
        .unwrap_or_else(|| panic!("no `lines` array in slice output:\n{stdout}"));

    assert!(
        lines.contains(&4),
        "backward slice of `return acc` must include line 4 (`acc += v`) — the \
         compound assignment reads and writes the accumulator; got slice lines \
         {lines:?}"
    );
}
