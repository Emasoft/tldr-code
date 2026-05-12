//! scala-column-unification-v1 (v0.4.1 bug-B): unify column emission so
//! `tldr definition`, `tldr references`, and `tldr api-check` all return
//! 1-indexed columns that agree for the same Scala symbol.
//!
//! Pre-fix the AGG19 audit (BUG-P19-06 family follow-up) flagged:
//!   - `tldr definition` returned `column: 0`-indexed (raw
//!     `tree_sitter::Point::column`) for Scala variables / parameters
//!     resolved by the local-scope scanners (`scan_scala_scope` →
//!     `make_param_location` / `make_var_location` at definition.rs:923
//!     / definition.rs:1195). The earlier BUG-P19-06 fix introduced
//!     `locate_symbol_column` and only patched the `funcs/classes`
//!     table-driven path; all 9 sites that emit
//!     `<node>.start_position().column as u32` directly remained 0-indexed.
//!   - `tldr api-check` (`check_regex_rule` at api_check.rs:2477) returned
//!     `regex.find(line_text).map(|m| m.start()).unwrap_or(0) as u32`,
//!     which is the 0-indexed byte offset within the trimmed line.
//!   - `tldr references` was already 1-indexed throughout
//!     (`crates/tldr-core/src/analysis/references.rs`, 18 sites all do
//!     `start_position().column + 1`).
//!
//! After this fix, the same Scala parameter / variable / api-check finding
//! has columns >= 1 across all three commands and agrees with references.
//!
//! Real-repo gated per `no-synthetic-fixtures-v1`: every test below
//! returns early if `/tmp/repos/scala-cats-effect` (or `/tmp/repos/ripgrep`
//! for the non-regression case) is absent.

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
    serde_json::from_str(out).unwrap_or(serde_json::Value::Null)
}

// Canonical Scala fixture: `def apply(i: Int): ExitCode = new ExitCode(i & 0xff) {}`
// on line 35 of ExitCode.scala. The parameter `i` starts at byte offset 12
// (0-indexed) / 13 (1-indexed) of that line.
const SCALA_FILE: &str =
    "/tmp/repos/scala-cats-effect/core/shared/src/main/scala/cats/effect/ExitCode.scala";
const SCALA_PARAM_LINE: u32 = 35;
const SCALA_PARAM_NAME: &str = "i";
const SCALA_PARAM_COL_ONE_INDEXED: u64 = 13;

// ============================================================================
// 1. `tldr definition` (position-based, local-scope) emits 1-indexed columns
//    for Scala parameters.
// ============================================================================
#[test]
fn scala_definition_column_one_indexed() {
    if !Path::new(SCALA_FILE).exists() {
        return;
    }
    // Pick a column that lands on the `i` in `apply(i: Int)`. The actual
    // hit-column passed to `tldr definition` is 1-indexed per the CLI
    // (the column arg `13` is the 1-indexed position of `i`).
    let line = format!("{}", SCALA_PARAM_LINE);
    let col_arg = format!("{}", SCALA_PARAM_COL_ONE_INDEXED);
    let (rc, out) = run_tldr(&[
        "definition",
        SCALA_FILE,
        &line,
        &col_arg,
        "--format",
        "json",
    ]);
    assert_eq!(rc, 0, "definition exit code; stdout: {}", out);
    let v = parse_json(&out);
    let col = v["definition"]["column"]
        .as_u64()
        .expect("definition.column must be a number");
    // Pre-fix: 12 (0-indexed). Post-fix: 13 (1-indexed).
    assert!(
        col >= 1,
        "definition column must be >= 1 (1-indexed); got {}",
        col
    );
    assert_eq!(
        col, SCALA_PARAM_COL_ONE_INDEXED,
        "definition column must match the 1-indexed position of `{}`",
        SCALA_PARAM_NAME
    );
}

// ============================================================================
// 2. `tldr references` emits 1-indexed columns AND agrees with definition
//    for the same Scala symbol.
// ============================================================================
#[test]
fn scala_references_column_one_indexed_and_agrees_with_definition() {
    if !Path::new(SCALA_FILE).exists() {
        return;
    }
    let (rc, out) = run_tldr(&[
        "references",
        SCALA_PARAM_NAME,
        SCALA_FILE,
        "--format",
        "json",
    ]);
    assert_eq!(rc, 0, "references exit code; stdout: {}", out);
    let v = parse_json(&out);
    // Find the reference whose line matches SCALA_PARAM_LINE.
    let refs = v["references"].as_array().cloned().unwrap_or_default();
    let on_line: Vec<u64> = refs
        .iter()
        .filter(|r| r["line"].as_u64() == Some(SCALA_PARAM_LINE as u64))
        .filter_map(|r| r["column"].as_u64())
        .collect();
    assert!(
        !on_line.is_empty(),
        "expected at least one reference of `{}` on line {}; got refs={:?}",
        SCALA_PARAM_NAME,
        SCALA_PARAM_LINE,
        refs
    );
    // Every reference column on that line must be 1-indexed (>= 1).
    for c in &on_line {
        assert!(
            *c >= 1,
            "reference column must be >= 1; got {} (refs: {:?})",
            c,
            on_line
        );
    }
    // The first reference column on that line must equal the definition's
    // 1-indexed column.
    assert_eq!(
        on_line[0], SCALA_PARAM_COL_ONE_INDEXED,
        "first reference column on line {} must agree with definition's 1-indexed column",
        SCALA_PARAM_LINE
    );

    // Cross-check against definition (same symbol, same file).
    let line_s = format!("{}", SCALA_PARAM_LINE);
    let col_s = format!("{}", SCALA_PARAM_COL_ONE_INDEXED);
    let (rc2, out2) = run_tldr(&[
        "definition",
        SCALA_FILE,
        &line_s,
        &col_s,
        "--format",
        "json",
    ]);
    assert_eq!(rc2, 0, "definition exit code; stdout: {}", out2);
    let v2 = parse_json(&out2);
    let def_col = v2["definition"]["column"]
        .as_u64()
        .expect("definition.column must be a number");
    assert_eq!(
        def_col, on_line[0],
        "definition.column ({}) must agree with first references.column ({}) on line {}",
        def_col, on_line[0], SCALA_PARAM_LINE
    );
}

// ============================================================================
// 3. `tldr api-check` emits 1-indexed columns for Scala findings.
// ============================================================================
#[test]
fn scala_api_check_column_one_indexed() {
    // IOPlatform.scala line 83: `      if (result eq null) {`. After
    // trimming the leading spaces, `null` is at byte offset 14
    // (0-indexed) of the trimmed line; 1-indexed = 15.
    let file = "/tmp/repos/scala-cats-effect/core/jvm-native/src/main/scala/cats/effect/IOPlatform.scala";
    if !Path::new(file).exists() {
        return;
    }
    let (rc, out) = run_tldr(&["api-check", file, "--format", "json"]);
    assert_eq!(rc, 0, "api-check exit code; stdout: {}", out);
    let v = parse_json(&out);
    let findings = v["findings"].as_array().cloned().unwrap_or_default();
    assert!(
        !findings.is_empty(),
        "expected at least one api-check finding on IOPlatform.scala"
    );
    for f in &findings {
        let col = f["column"]
            .as_u64()
            .expect("finding.column must be a number");
        assert!(
            col >= 1,
            "api-check column must be >= 1 (1-indexed); got {} for finding {:?}",
            col,
            f
        );
    }
    // Specifically the SC001 `null` finding on line 83 should be at
    // 1-indexed column 15 (trimmed line, position of `null`).
    let sc001_on_83: Vec<u64> = findings
        .iter()
        .filter(|f| {
            f["line"].as_u64() == Some(83)
                && f["rule"]["id"].as_str() == Some("SC001")
        })
        .filter_map(|f| f["column"].as_u64())
        .collect();
    if !sc001_on_83.is_empty() {
        assert_eq!(
            sc001_on_83[0], 15,
            "SC001 `null` on IOPlatform.scala:83 must be at 1-indexed column 15 (pre-fix was 14)"
        );
    }
}

// ============================================================================
// 4. Non-regression: Rust columns remain 1-indexed and consistent
//    (verifies the fix is uniform, not Scala-only).
// ============================================================================
#[test]
fn non_regression_rust_column_still_one_indexed() {
    let rust_file = "/tmp/repos/ripgrep/crates/globset/src/lib.rs";
    if !Path::new(rust_file).exists() {
        return;
    }
    let (rc, out) = run_tldr(&["api-check", rust_file, "--format", "json"]);
    assert_eq!(rc, 0, "api-check exit code on rust; stdout: {}", out);
    let v = parse_json(&out);
    let findings = v["findings"].as_array().cloned().unwrap_or_default();
    // ripgrep/crates/globset/src/lib.rs has 2 known findings (RS005, RS006).
    assert!(
        !findings.is_empty(),
        "expected at least one rust api-check finding on globset/src/lib.rs"
    );
    for f in &findings {
        let col = f["column"]
            .as_u64()
            .expect("rust finding.column must be a number");
        assert!(
            col >= 1,
            "rust api-check column must be >= 1 (1-indexed); got {} for finding {:?}",
            col,
            f
        );
    }
}

// ============================================================================
// 5. Negative-control: ensure the fix does not over-shift columns. The
//    pre-fix value for the Scala `i` parameter was 12; post-fix must be
//    exactly 13 (not 14). Guards against accidentally adding `+ 1` twice.
// ============================================================================
#[test]
fn scala_definition_column_not_double_incremented() {
    if !Path::new(SCALA_FILE).exists() {
        return;
    }
    let line = format!("{}", SCALA_PARAM_LINE);
    let col_arg = format!("{}", SCALA_PARAM_COL_ONE_INDEXED);
    let (rc, out) = run_tldr(&[
        "definition",
        SCALA_FILE,
        &line,
        &col_arg,
        "--format",
        "json",
    ]);
    assert_eq!(rc, 0, "definition exit code; stdout: {}", out);
    let v = parse_json(&out);
    let col = v["definition"]["column"]
        .as_u64()
        .expect("definition.column must be a number");
    assert!(
        col <= SCALA_PARAM_COL_ONE_INDEXED,
        "definition column must not exceed 1-indexed position; got {} (expected {})",
        col,
        SCALA_PARAM_COL_ONE_INDEXED
    );
}
