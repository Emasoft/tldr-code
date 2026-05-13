//! cross-lang-definition-column-v1 (v0.4.2 bug-A1-A2-A4): extend
//! scala-column-unification-v1 (M2, commit `344845e`) to the non-Scala
//! definition paths flagged by the v0.4.2 audit (reviewer A / reviewer C):
//!
//!   - java audit cell c45 (reclassified FAIL): `tldr definition --file
//!     OwnerController.java --symbol processFindForm` returned
//!     `column: 0`. Root cause: tree-sitter-java's `method_declaration`
//!     `start_position()` is the line of the leading annotation
//!     (`@GetMapping("/owners")`), not the method header line, so the
//!     `locate_symbol_column` lookup on that line fails (the symbol name
//!     is not on the annotation line) and the column defaults to 0.
//!
//!   - kotlin audit CF-KT-03: `tldr definition --file DateTimePeriod.kt
//!     --symbol toDateTimePeriod` returned `column: 0` for an
//!     annotation-decorated public top-level function. Same root cause
//!     class as java — the kotlin callgraph extractor reports
//!     `function_declaration.start_position()` which includes the
//!     leading `@Deprecated(...)` modifier line.
//!
//!   - scala audit (reviewer C): `tldr definition --file IO.scala
//!     --symbol interpret` returned `column: 0` for a Scala method whose
//!     `@deprecated(...)` annotation occupies the line before the
//!     `def interpret[...]` header. M2 fixed Scala parameter / variable
//!     local-scope paths but did NOT cover the table-driven path used
//!     for top-level methods carried as `FuncDef`/`ClassDef` whose `line`
//!     points at the annotation rather than the `def` keyword.
//!
//! Strategy: harden `locate_symbol_column` in
//! `crates/tldr-cli/src/commands/remaining/definition.rs` so that when
//! the symbol name does not appear on the `FuncDef`-reported line, it
//! scans forward up to a small bounded window for the symbol and
//! returns the corrected `(line, column)`. The line carried in
//! `FuncDef`/`ClassDef` is overridden to the line the symbol actually
//! lives on, and the column is 1-indexed per `references.rs` /
//! `scala-column-unification-v1`.
//!
//! Non-regression: the existing Scala parameter case
//! (ExitCode.scala:35 / `i` at col 13) must still resolve to col 13 —
//! that path goes through the local-scope scanner already patched by M2
//! and is not affected by the `locate_symbol_column` change.
//!
//! Real-repo gated per `no-synthetic-fixtures-v1`. Every test below
//! returns early if its target repo is absent.

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

// ============================================================================
// Fixtures (real repos, audit-sourced symbols)
// ============================================================================

const JAVA_FILE: &str = "/tmp/repos/spring-petclinic/src/main/java/org/springframework/samples/petclinic/owner/OwnerController.java";
const JAVA_SYMBOL: &str = "processFindForm";
// `@GetMapping("/owners")` is on line 94; `public String processFindForm(...)`
// header is on line 95. Pre-fix tldr returned line=94, col=0. Post-fix it
// must point at the actual method header with a 1-indexed column.
const JAVA_HEADER_LINE: u64 = 95;

const KOTLIN_FILE: &str = "/tmp/repos/kotlin-datetime/core/common/src/DateTimePeriod.kt";
const KOTLIN_SYMBOL: &str = "toDateTimePeriod";
// `@Deprecated(...)` is on line 477; `public fun String.toDateTimePeriod():
// DateTimePeriod = ...` header is on line 478. Pre-fix tldr returned
// line=477, col=0.
const KOTLIN_HEADER_LINE: u64 = 478;

const SCALA_IO_FILE: &str =
    "/tmp/repos/scala-cats-effect/core/shared/src/main/scala/cats/effect/IO.scala";
const SCALA_IO_SYMBOL: &str = "interpret";
// `@deprecated("retained for bincompat", "3.6.1")` is on line 2343; the
// `def interpret[G[+_], B](io: IO[B], limit: Int)(...)` header begins on
// line 2344. Pre-fix tldr returned line=2343, col=0.
const SCALA_IO_HEADER_LINE: u64 = 2344;

// Non-regression: M2's canonical Scala parameter case. ExitCode.scala
// line 35 — `def apply(i: Int): ExitCode = new ExitCode(i & 0xff) {}`.
// `i` is at 1-indexed column 13.
const SCALA_EXITCODE_FILE: &str =
    "/tmp/repos/scala-cats-effect/core/shared/src/main/scala/cats/effect/ExitCode.scala";
const SCALA_EXITCODE_PARAM_LINE: u32 = 35;
const SCALA_EXITCODE_PARAM_COL: u64 = 13;

// ============================================================================
// 1. java: processFindForm definition column must be >= 1, and the line
//    must be the method header line (95), not the annotation line (94).
// ============================================================================
#[test]
fn java_definition_column_one_indexed() {
    if !Path::new(JAVA_FILE).exists() {
        return;
    }
    let (rc, out) = run_tldr(&[
        "definition",
        "--file",
        JAVA_FILE,
        "--symbol",
        JAVA_SYMBOL,
        "--format",
        "json",
    ]);
    assert_eq!(rc, 0, "definition exit code; stdout: {}", out);
    let v = parse_json(&out);
    let line = v["definition"]["line"]
        .as_u64()
        .expect("definition.line must be a number");
    let col = v["definition"]["column"]
        .as_u64()
        .expect("definition.column must be a number");
    assert_eq!(
        line, JAVA_HEADER_LINE,
        "java definition line must point at the method header (post-fix), not the annotation line; got {}",
        line
    );
    assert!(
        col >= 1,
        "java definition column must be >= 1 (1-indexed); got {}",
        col
    );
}

// ============================================================================
// 2. kotlin: toDateTimePeriod definition column must be >= 1, and the
//    line must be the `public fun` header (478), not the `@Deprecated`
//    annotation line (477).
// ============================================================================
#[test]
fn kotlin_definition_column_one_indexed() {
    if !Path::new(KOTLIN_FILE).exists() {
        return;
    }
    let (rc, out) = run_tldr(&[
        "definition",
        "--file",
        KOTLIN_FILE,
        "--symbol",
        KOTLIN_SYMBOL,
        "--format",
        "json",
    ]);
    assert_eq!(rc, 0, "definition exit code; stdout: {}", out);
    let v = parse_json(&out);
    let line = v["definition"]["line"]
        .as_u64()
        .expect("definition.line must be a number");
    let col = v["definition"]["column"]
        .as_u64()
        .expect("definition.column must be a number");
    assert_eq!(
        line, KOTLIN_HEADER_LINE,
        "kotlin definition line must point at the function header (post-fix), not the annotation line; got {}",
        line
    );
    assert!(
        col >= 1,
        "kotlin definition column must be >= 1 (1-indexed); got {}",
        col
    );
}

// ============================================================================
// 3. kotlin: the line must NOT be the `@Deprecated(...)` annotation line.
//    Stronger version of test 2 — explicitly guards against regressions
//    that would re-emit the annotation line.
// ============================================================================
#[test]
fn kotlin_definition_points_at_header_not_annotation() {
    if !Path::new(KOTLIN_FILE).exists() {
        return;
    }
    let (rc, out) = run_tldr(&[
        "definition",
        "--file",
        KOTLIN_FILE,
        "--symbol",
        KOTLIN_SYMBOL,
        "--format",
        "json",
    ]);
    assert_eq!(rc, 0, "definition exit code; stdout: {}", out);
    let v = parse_json(&out);
    let line = v["definition"]["line"]
        .as_u64()
        .expect("definition.line must be a number");
    assert!(
        line >= KOTLIN_HEADER_LINE,
        "kotlin definition line must be at or after the header line (post-fix), got {} (annotation line is {})",
        line,
        KOTLIN_HEADER_LINE - 1
    );
    // Read source line and verify it is the `public fun` header, not
    // `@Deprecated`.
    let content = std::fs::read_to_string(KOTLIN_FILE).expect("read kotlin source");
    let line_text = content
        .lines()
        .nth((line as usize).saturating_sub(1))
        .unwrap_or("");
    assert!(
        !line_text.trim_start().starts_with('@'),
        "kotlin definition must not land on an annotation line; got line text: {}",
        line_text
    );
    assert!(
        line_text.contains(KOTLIN_SYMBOL),
        "kotlin definition line must contain the symbol name; got: {}",
        line_text
    );
}

// ============================================================================
// 4. scala (annotation-decorated method): interpret definition column
//    must be >= 1, and the line must be the `def interpret` header
//    (2344), not the `@deprecated` annotation line (2343).
// ============================================================================
#[test]
fn scala_annotation_decorated_definition_column_one_indexed() {
    if !Path::new(SCALA_IO_FILE).exists() {
        return;
    }
    let (rc, out) = run_tldr(&[
        "definition",
        "--file",
        SCALA_IO_FILE,
        "--symbol",
        SCALA_IO_SYMBOL,
        "--format",
        "json",
    ]);
    assert_eq!(rc, 0, "definition exit code; stdout: {}", out);
    let v = parse_json(&out);
    let line = v["definition"]["line"]
        .as_u64()
        .expect("definition.line must be a number");
    let col = v["definition"]["column"]
        .as_u64()
        .expect("definition.column must be a number");
    assert_eq!(
        line, SCALA_IO_HEADER_LINE,
        "scala definition line must point at the `def interpret` header (post-fix), not the @deprecated line; got {}",
        line
    );
    assert!(
        col >= 1,
        "scala definition column must be >= 1 (1-indexed); got {}",
        col
    );
}

// ============================================================================
// 5. non-regression: M2 fix (scala parameter via local-scope scanner)
//    must still emit col=13 for ExitCode.scala `i` parameter on line 35.
// ============================================================================
#[test]
fn scala_parameter_definition_still_one_indexed() {
    if !Path::new(SCALA_EXITCODE_FILE).exists() {
        return;
    }
    let line = format!("{}", SCALA_EXITCODE_PARAM_LINE);
    let col_arg = format!("{}", SCALA_EXITCODE_PARAM_COL);
    let (rc, out) = run_tldr(&[
        "definition",
        SCALA_EXITCODE_FILE,
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
    assert_eq!(
        col, SCALA_EXITCODE_PARAM_COL,
        "M2 non-regression: scala parameter `i` column must still be {} (1-indexed) post-fix",
        SCALA_EXITCODE_PARAM_COL
    );
}
