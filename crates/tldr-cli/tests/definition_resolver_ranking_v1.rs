//! definition-resolver-ranking-v1 (v0.4.2 M-040): rank `definition`
//! results so the resolver picks the "real" definition rather than the
//! first textual match. This is the next iteration in the
//! first-textual-match family (M-013/M-019/M-027/M-026) — those covered
//! qualified-name, FuncIndex-aware explain callees, and the
//! search↔calls-index join. M-040 covers the `definition` command itself.
//!
//! Audit cells in scope (3 langs):
//!
//!   - cpp c45 — `tldr definition --symbol XMLDocument
//!     /tmp/repos/cpp-tinyxml2/tinyxml2.h` returned the forward
//!     declaration `class XMLDocument;` at line 113 instead of the
//!     real class body `class TINYXML2_LIB XMLDocument : public XMLNode
//!     { ... }` at line 1715. The pre-fix output also tolerated the
//!     `friend class XMLDocument;` declaration at line 668 being picked
//!     under earlier handler variants (`kind: "variable"` in the
//!     reviewer's audit JSON). The post-fix policy: prefer
//!     class_specifier nodes carrying a `field_declaration_list` body
//!     over forward/friend declarations.
//!
//!   - elixir c41 — `tldr definition --symbol send_resp
//!     /tmp/repos/elixir-plug/lib/plug/conn.ex` returned line 437,
//!     which is the bodyless `def send_resp(conn)` declaration that
//!     introduces the @spec for the function. The actual clauses with
//!     `do ... end` bodies live at lines 439, 443, and 453. Post-fix
//!     the resolver must skip bodyless `def`/`defp` calls and return
//!     the first clause that carries a `do_block`.
//!
//!   - scala c44 — `tldr definition .../ExitCode.scala 35 14` (a
//!     cursor on the whitespace right after `i:` on the line
//!     `def apply(i: Int): ExitCode = ...`) errored with
//!     `symbol '' not found in scope`. The
//!     `extract_identifier_at_column` fallback only looked one byte
//!     to the LEFT for an adjacent identifier; if that byte was a
//!     non-ident punctuation (`:` in this case) it gave up. Post-fix
//!     the fallback also scans a few bytes farther in either
//!     direction so single-char identifiers next to punctuation
//!     resolve.
//!
//! Non-regression contract: `scala_column_unification_v1.rs` MUST
//! remain green — the M2 column-unification work (parameter `i` at
//! col 13 resolves to itself, 1-indexed) is preserved.
//!
//! Real-repo gated per `no-synthetic-fixtures-v1`: each test returns
//! early if its target repo is absent. The release binary is invoked
//! exactly as in production (no per-test crates / no test-only knobs).

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

fn run_tldr(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(tldr_bin())
        .args(args)
        .output()
        .expect("failed to run tldr binary");
    let exit = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    (exit, stdout, stderr)
}

fn parse_json(out: &str) -> serde_json::Value {
    serde_json::from_str(out).unwrap_or(serde_json::Value::Null)
}

// ============================================================================
// Fixtures (real repos, audit-sourced)
// ============================================================================

const CPP_FILE: &str = "/tmp/repos/cpp-tinyxml2/tinyxml2.h";
const CPP_SYMBOL: &str = "XMLDocument";
// The forward declaration sits at line 113 (`class XMLDocument;`); the
// `friend class XMLDocument;` declarations are at 668/991/1031/1070/1105/
// 1264; the real class body — the one the user wants — begins at line
// 1715 (`class TINYXML2_LIB XMLDocument : public XMLNode { ... }`).
// (corpus-drift-fix-v1: tinyxml2.h shifted 3 lines upstream; constants
// updated from 116/994/1718 to 113/668/1715 to match current shallow clone.)
const CPP_FORWARD_LINE: u64 = 113;
const CPP_FRIEND_LINE: u64 = 668;
const CPP_REAL_BODY_LINE: u64 = 1715;

const ELIXIR_FILE: &str = "/tmp/repos/elixir-plug/lib/plug/conn.ex";
const ELIXIR_SYMBOL: &str = "send_resp";
// Line 437 is the bodyless `def send_resp(conn)` callback header; the
// first real clause carrying a `do_block` is at line 439. Other
// clauses live at 443 and 453.
const ELIXIR_BODYLESS_LINE: u64 = 437;
const ELIXIR_FIRST_CLAUSE_LINE: u64 = 439;

const SCALA_FILE: &str =
    "/tmp/repos/scala-cats-effect/core/shared/src/main/scala/cats/effect/ExitCode.scala";
// Line 35: `  def apply(i: Int): ExitCode = new ExitCode(i & 0xff) {}`
//          0123456789012345678901234567890
//                    1111111111222222222
// 1-indexed columns:
//   13 → `i` (the parameter declaration; canonical M2 expectation)
//   14 → `:` (punctuation; cursor sits ON the colon)
//   15 → ` ` (whitespace between `:` and `Int`)
const SCALA_PARAM_LINE: u32 = 35;
const SCALA_PARAM_DECL_COL: u64 = 13;

// ============================================================================
// 1. cpp: XMLDocument must resolve to the real class body (line 1718),
//    NOT the forward declaration (line 116) and NOT a friend declaration.
// ============================================================================
#[test]
fn cpp_definition_picks_class_body_over_forward_decl() {
    if !Path::new(CPP_FILE).exists() {
        return;
    }
    let (rc, out, err) = run_tldr(&[
        "definition",
        "--file",
        CPP_FILE,
        "--symbol",
        CPP_SYMBOL,
        "--lang",
        "cpp",
        "--format",
        "json",
    ]);
    assert_eq!(rc, 0, "definition exit code; stderr: {}", err);
    let v = parse_json(&out);
    let line = v["definition"]["line"]
        .as_u64()
        .expect("definition.line must be a number");
    let kind = v["symbol"]["kind"].as_str().unwrap_or("");

    assert_ne!(
        line, CPP_FORWARD_LINE,
        "cpp definition must NOT pick the forward declaration at line {} (the real class body is at line {})",
        CPP_FORWARD_LINE, CPP_REAL_BODY_LINE
    );
    assert_ne!(
        line, CPP_FRIEND_LINE,
        "cpp definition must NOT pick the `friend class {};` decl at line {}",
        CPP_SYMBOL, CPP_FRIEND_LINE
    );
    assert_eq!(
        line, CPP_REAL_BODY_LINE,
        "cpp definition must pick the real class body at line {}; got {}",
        CPP_REAL_BODY_LINE, line
    );
    assert_eq!(
        kind, "class",
        "cpp XMLDocument kind must be `class` (real class body), not `{}`",
        kind
    );
}

// ============================================================================
// 2. elixir: send_resp must resolve to the FIRST clause that carries a
//    `do ... end` body, not the bodyless `def send_resp(conn)` header
//    that introduces the @spec.
// ============================================================================
#[test]
fn elixir_definition_picks_def_clause_over_bodyless_header() {
    if !Path::new(ELIXIR_FILE).exists() {
        return;
    }
    let (rc, out, err) = run_tldr(&[
        "definition",
        "--file",
        ELIXIR_FILE,
        "--symbol",
        ELIXIR_SYMBOL,
        "--lang",
        "elixir",
        "--format",
        "json",
    ]);
    assert_eq!(rc, 0, "definition exit code; stderr: {}", err);
    let v = parse_json(&out);
    let line = v["definition"]["line"]
        .as_u64()
        .expect("definition.line must be a number");
    let kind = v["symbol"]["kind"].as_str().unwrap_or("");

    assert_ne!(
        line, ELIXIR_BODYLESS_LINE,
        "elixir definition must NOT pick the bodyless `def {}` callback header at line {}; the first real clause carrying a `do` body is at line {}",
        ELIXIR_SYMBOL, ELIXIR_BODYLESS_LINE, ELIXIR_FIRST_CLAUSE_LINE
    );
    assert_eq!(
        line, ELIXIR_FIRST_CLAUSE_LINE,
        "elixir definition must pick the first `def {}` clause with a body at line {}; got {}",
        ELIXIR_SYMBOL, ELIXIR_FIRST_CLAUSE_LINE, line
    );
    // Elixir defs are reported as either `function` (top-level) or
    // `method` (when nested inside a `defmodule`). Both are
    // acceptable; what's NOT acceptable is a non-callable kind like
    // `variable` or `class`.
    assert!(
        kind == "function" || kind == "method",
        "elixir send_resp kind must be `function` or `method`; got `{}`",
        kind
    );
}

// ============================================================================
// 3. scala: cursor on the `:` immediately following the single-char
//    identifier `i` must still resolve `i` (not error out with an
//    empty symbol). Re-validates the M2 column-unification claim that
//    single-char identifiers participate in the resolver — the audit
//    cell c44 reported pre-fix `symbol '' not found in scope` for this
//    exact position.
// ============================================================================
#[test]
fn scala_single_char_identifier_resolves_when_cursor_on_adjacent_punctuation() {
    if !Path::new(SCALA_FILE).exists() {
        return;
    }
    // Column 14 (1-indexed) sits on the `:` immediately after the
    // single-char `i` parameter declaration. Pre-fix this errored
    // with `symbol '' not found in scope` because the cursor's
    // tokenizer fallback only checked the byte immediately to the
    // left for an adjacent identifier; if it was a non-ident
    // punctuation (here the `:`), the resolver gave up. The cluster
    // M-040 scala arm requires that `i` is found.
    let col: u32 = 14;
    let line_str = SCALA_PARAM_LINE.to_string();
    let col_str = col.to_string();
    let (rc, out, err) = run_tldr(&[
        "definition",
        SCALA_FILE,
        &line_str,
        &col_str,
        "--lang",
        "scala",
        "--format",
        "json",
    ]);
    assert_eq!(
        rc, 0,
        "scala definition at {}:{} must succeed; stderr: {}",
        SCALA_PARAM_LINE, col, err
    );
    let v = parse_json(&out);
    let name = v["symbol"]["name"].as_str().unwrap_or("");
    let resolved_col = v["definition"]["column"]
        .as_u64()
        .expect("definition.column must be a number");
    assert_eq!(
        name, "i",
        "scala definition at {}:{} must resolve symbol `i`; got `{}`",
        SCALA_PARAM_LINE, col, name
    );
    assert_eq!(
        resolved_col, SCALA_PARAM_DECL_COL,
        "scala `i` must resolve to its declaration column ({}); got {}",
        SCALA_PARAM_DECL_COL, resolved_col
    );
}

// ============================================================================
// 4. scala non-regression: M2's canonical case still passes — cursor
//    exactly on `i` at col 13 resolves to col 13.
// ============================================================================
#[test]
fn scala_param_decl_col_13_unchanged() {
    if !Path::new(SCALA_FILE).exists() {
        return;
    }
    let line_str = SCALA_PARAM_LINE.to_string();
    let col_str = "13";
    let (rc, out, err) = run_tldr(&[
        "definition",
        SCALA_FILE,
        &line_str,
        col_str,
        "--lang",
        "scala",
        "--format",
        "json",
    ]);
    assert_eq!(rc, 0, "scala definition at 35:13 must succeed; stderr: {}", err);
    let v = parse_json(&out);
    let name = v["symbol"]["name"].as_str().unwrap_or("");
    let resolved_col = v["definition"]["column"]
        .as_u64()
        .expect("definition.column must be a number");
    assert_eq!(name, "i");
    assert_eq!(resolved_col, SCALA_PARAM_DECL_COL);
}
