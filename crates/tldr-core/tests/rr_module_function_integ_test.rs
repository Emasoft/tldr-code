//! field_access_info-extension-v1 — M1 RED integration tests for
//! Ruby/Elixir/OCaml `Module.function(...)` taint shapes.
//!
//! Each Module.function test runs through TWO dispatch paths:
//!
//! 1. `analyze_with_ssa(...)` (regular) — exercises both AST and regex banks.
//!    PASSES at HEAD pre-M2/M3/M4 because the regex banks
//!    (`RUBY_PATTERNS`/`ELIXIR_PATTERNS`/`OCAML_PATTERNS`) still catch the
//!    Module.function shape via substring patterns. This is the additive
//!    coverage proof that the rewrite does not regress today's behavior.
//!
//! 2. `analyze_ast_only(...)` (AST-only) — activates an
//!    `AstOnlyTestModeGuard` (defined in
//!    `tldr_core::security::taint`) that transiently empties the regex
//!    `.sources` / `.sinks` banks for the duration of the call. This isolates
//!    the AST detection path. FAILS at HEAD pre-M2/M3/M4 because the
//!    `RUBY_AST_*` / `ELIXIR_AST_*` / `OCAML_AST_*` retain entries for these
//!    shapes use the raw-substring `("", "Module.fn")` form which is skipped
//!    by both the structural (`field_access_info`) and the W2-pre call-shape
//!    paths in `member_patterns_match` (`taint.rs:2989-3009`).
//!
//! This dual-path setup is the gating RED for M2/M3/M4: when each language's
//! structured-shape rewrite (`("Module", "fn")`) lands in
//! `RUBY_AST_*`/`ELIXIR_AST_*`/`OCAML_AST_*`, the corresponding fixtures
//! transition FAIL→PASS under `analyze_ast_only`. After M5 deletes the regex
//! banks, the regular `analyze_with_ssa` path collapses to the same behavior
//! as `analyze_ast_only`.
//!
//! The 3 string-literal regression-guard tests (`*_string_literal_*_zero_findings`)
//! must PASS on BOTH paths — they assert that fixtures where `IO.popen` /
//! `System.cmd` / `Sys.command` appear ONLY inside string-literal text never
//! trigger a finding. They are the closes-#24 generalization to Ruby/Elixir/
//! OCaml and must stay GREEN through M5.
//!
//! Test count: 6 Ruby Module.function + 7 Elixir Module.function + 5 OCaml
//! Module.function (1 of which uses the bare-call `read_line` source path,
//! not a Module.function rewrite) + 3 string-literal regression guards = 21
//! tests in this file. Per-language baseline augmentation (3 tests) is in
//! `rr_baseline_per_language_test.rs`.

use tldr_core::{Language, TaintInfo, TaintSinkType, TaintSourceType};

#[path = "common/integ_helpers.rs"]
mod common;

use common::{analyze_ast_only, analyze_with_ssa};

// ---------------------------------------------------------------------------
// Local helpers — small, file-private. These mirror the assertion shape used
// by `rr_baseline_per_language_test.rs` (filter sinks by type, assert
// non-empty), with `result` / `path` arguments so callers can pass either
// `analyze` or `analyze_ast_only` outputs through the same predicate.
// ---------------------------------------------------------------------------

fn assert_has_source_of_type(result: &TaintInfo, expected: TaintSourceType, path: &str) {
    let lines: Vec<u32> = result
        .sources
        .iter()
        .filter(|s| s.source_type == expected)
        .map(|s| s.line)
        .collect();
    assert!(
        !lines.is_empty(),
        "[{path}] expected at least one {:?} source; got sources={:?}",
        expected,
        result.sources
    );
}

fn assert_has_sink_of_type(result: &TaintInfo, expected: TaintSinkType, path: &str) {
    let lines: Vec<u32> = result
        .sinks
        .iter()
        .filter(|s| s.sink_type == expected)
        .map(|s| s.line)
        .collect();
    assert!(
        !lines.is_empty(),
        "[{path}] expected at least one {:?} sink; got sinks={:?}",
        expected,
        result.sinks
    );
}

fn assert_has_source_or_sink(
    result: &TaintInfo,
    source: TaintSourceType,
    sink: TaintSinkType,
    path: &str,
) {
    assert_has_source_of_type(result, source, path);
    assert_has_sink_of_type(result, sink, path);
}

// ===========================================================================
// Ruby (6 Module.function fixtures)
// ===========================================================================

/// Ruby: `cmd = STDIN.read; eval(cmd)` — Stdin source via `STDIN.read` Module
/// call -> CodeEval sink via bare `eval`. The `eval` sink is detected via
/// `RUBY_AST_SINKS` `call_names: ["eval"]` (already AST-native), so the
/// AST-only failure point is purely the `STDIN.read` source side.
#[test]
fn ruby_stdin_read_to_eval_via_compute_taint() {
    let src = "\
def handler
    cmd = STDIN.read
    eval(cmd)
end
";
    // (a) regular path: PASSES at HEAD via regex bank
    let regular = analyze_with_ssa(src, Language::Ruby, "handler", /* use_ssa */ false);
    assert_has_source_or_sink(
        &regular,
        TaintSourceType::Stdin,
        TaintSinkType::CodeEval,
        "regular",
    );
    // (b) AST-only path: FAILS at HEAD pre-M2 (RED gate; M2 turns GREEN)
    let ast_only = analyze_ast_only(src, Language::Ruby, "handler");
    assert_has_source_of_type(&ast_only, TaintSourceType::Stdin, "ast_only");
    assert_has_sink_of_type(&ast_only, TaintSinkType::CodeEval, "ast_only");
}

/// Ruby: `cmd = STDIN.gets; system(cmd)` — Stdin source via `STDIN.gets`
/// Module call -> ShellExec sink via bare `system` call.
#[test]
fn ruby_stdin_gets_to_system_via_compute_taint() {
    let src = "\
def handler
    cmd = STDIN.gets
    system(cmd)
end
";
    let regular = analyze_with_ssa(src, Language::Ruby, "handler", false);
    assert_has_source_of_type(&regular, TaintSourceType::Stdin, "regular");
    assert_has_sink_of_type(&regular, TaintSinkType::ShellExec, "regular");
    let ast_only = analyze_ast_only(src, Language::Ruby, "handler");
    assert_has_source_of_type(&ast_only, TaintSourceType::Stdin, "ast_only");
    assert_has_sink_of_type(&ast_only, TaintSinkType::ShellExec, "ast_only");
}

/// Ruby: `cmd = STDIN.readline; IO.popen(cmd)` — Stdin source via
/// `STDIN.readline` Module call -> ShellExec sink via `IO.popen` Module
/// call. BOTH sides require structured Module.function matching — both fail
/// under AST-only at HEAD.
#[test]
fn ruby_stdin_readline_to_io_popen_via_compute_taint() {
    let src = "\
def handler
    cmd = STDIN.readline
    IO.popen(cmd)
end
";
    let regular = analyze_with_ssa(src, Language::Ruby, "handler", false);
    assert_has_source_of_type(&regular, TaintSourceType::Stdin, "regular");
    assert_has_sink_of_type(&regular, TaintSinkType::ShellExec, "regular");
    let ast_only = analyze_ast_only(src, Language::Ruby, "handler");
    assert_has_source_of_type(&ast_only, TaintSourceType::Stdin, "ast_only");
    assert_has_sink_of_type(&ast_only, TaintSinkType::ShellExec, "ast_only");
}

/// Ruby: `cmd = File.read("path"); eval(cmd)` — FileRead source via
/// `File.read` Module call -> CodeEval sink via bare `eval`.
#[test]
fn ruby_file_read_to_eval_via_compute_taint() {
    let src = "\
def handler
    cmd = File.read(\"path\")
    eval(cmd)
end
";
    let regular = analyze_with_ssa(src, Language::Ruby, "handler", false);
    assert_has_source_of_type(&regular, TaintSourceType::FileRead, "regular");
    assert_has_sink_of_type(&regular, TaintSinkType::CodeEval, "regular");
    let ast_only = analyze_ast_only(src, Language::Ruby, "handler");
    assert_has_source_of_type(&ast_only, TaintSourceType::FileRead, "ast_only");
    assert_has_sink_of_type(&ast_only, TaintSinkType::CodeEval, "ast_only");
}

/// Ruby: `cmd = File.open("path"); system(cmd)` — FileRead source via
/// `File.open` Module call -> ShellExec sink via bare `system`.
#[test]
fn ruby_file_open_to_system_via_compute_taint() {
    let src = "\
def handler
    cmd = File.open(\"path\")
    system(cmd)
end
";
    let regular = analyze_with_ssa(src, Language::Ruby, "handler", false);
    assert_has_source_of_type(&regular, TaintSourceType::FileRead, "regular");
    assert_has_sink_of_type(&regular, TaintSinkType::ShellExec, "regular");
    let ast_only = analyze_ast_only(src, Language::Ruby, "handler");
    assert_has_source_of_type(&ast_only, TaintSourceType::FileRead, "ast_only");
    assert_has_sink_of_type(&ast_only, TaintSinkType::ShellExec, "ast_only");
}

/// Ruby: bare `gets` (UserInput, AST-native via `call_names: ["gets"]`) ->
/// `IO.popen(cmd)` ShellExec sink. The sink side requires structured
/// Module.function matching — fails under AST-only at HEAD pre-M2.
#[test]
fn ruby_io_popen_with_user_input_via_compute_taint() {
    let src = "\
def handler
    cmd = gets
    IO.popen(cmd)
end
";
    let regular = analyze_with_ssa(src, Language::Ruby, "handler", false);
    assert_has_source_of_type(&regular, TaintSourceType::UserInput, "regular");
    assert_has_sink_of_type(&regular, TaintSinkType::ShellExec, "regular");
    let ast_only = analyze_ast_only(src, Language::Ruby, "handler");
    // Source side already AST-native; the failure point at HEAD is the sink.
    assert_has_source_of_type(&ast_only, TaintSourceType::UserInput, "ast_only");
    assert_has_sink_of_type(&ast_only, TaintSinkType::ShellExec, "ast_only");
}

// ===========================================================================
// Elixir (7 Module.function fixtures)
// ===========================================================================

/// Elixir: `cmd = IO.gets("> "); System.cmd(cmd, [])` — UserInput via
/// `IO.gets` Module call -> ShellExec via `System.cmd` Module call. Both
/// sides require structured Module.function matching.
#[test]
fn elixir_io_gets_to_system_cmd_via_compute_taint() {
    let src = "\
def handler do
  cmd = IO.gets(\"> \")
  System.cmd(cmd, [])
end
";
    let regular = analyze_with_ssa(src, Language::Elixir, "handler", false);
    assert_has_source_of_type(&regular, TaintSourceType::UserInput, "regular");
    assert_has_sink_of_type(&regular, TaintSinkType::ShellExec, "regular");
    let ast_only = analyze_ast_only(src, Language::Elixir, "handler");
    assert_has_source_of_type(&ast_only, TaintSourceType::UserInput, "ast_only");
    assert_has_sink_of_type(&ast_only, TaintSinkType::ShellExec, "ast_only");
}

/// Elixir: `name = System.get_env("X"); Code.eval_string(name)` — EnvVar
/// via `System.get_env` -> CodeEval via `Code.eval_string`.
#[test]
fn elixir_system_get_env_to_code_eval_via_compute_taint() {
    let src = "\
def handler do
  name = System.get_env(\"X\")
  Code.eval_string(name)
end
";
    let regular = analyze_with_ssa(src, Language::Elixir, "handler", false);
    assert_has_source_of_type(&regular, TaintSourceType::EnvVar, "regular");
    assert_has_sink_of_type(&regular, TaintSinkType::CodeEval, "regular");
    let ast_only = analyze_ast_only(src, Language::Elixir, "handler");
    assert_has_source_of_type(&ast_only, TaintSourceType::EnvVar, "ast_only");
    assert_has_sink_of_type(&ast_only, TaintSinkType::CodeEval, "ast_only");
}

/// Elixir: `cmd = File.read("path"); System.cmd(cmd, [])` — FileRead via
/// `File.read` -> ShellExec via `System.cmd`.
#[test]
fn elixir_file_read_to_system_cmd_via_compute_taint() {
    let src = "\
def handler do
  cmd = File.read(\"path\")
  System.cmd(cmd, [])
end
";
    let regular = analyze_with_ssa(src, Language::Elixir, "handler", false);
    assert_has_source_of_type(&regular, TaintSourceType::FileRead, "regular");
    assert_has_sink_of_type(&regular, TaintSinkType::ShellExec, "regular");
    let ast_only = analyze_ast_only(src, Language::Elixir, "handler");
    assert_has_source_of_type(&ast_only, TaintSourceType::FileRead, "ast_only");
    assert_has_sink_of_type(&ast_only, TaintSinkType::ShellExec, "ast_only");
}

/// Elixir: `cmd = File.read!("path"); System.cmd(cmd, [])` — FileRead via
/// `File.read!` (bang-suffix variant; tree-sitter-elixir parses `read!` as a
/// single identifier node) -> ShellExec via `System.cmd`.
#[test]
fn elixir_file_read_bang_to_system_cmd_via_compute_taint() {
    let src = "\
def handler do
  cmd = File.read!(\"path\")
  System.cmd(cmd, [])
end
";
    let regular = analyze_with_ssa(src, Language::Elixir, "handler", false);
    assert_has_source_of_type(&regular, TaintSourceType::FileRead, "regular");
    assert_has_sink_of_type(&regular, TaintSinkType::ShellExec, "regular");
    let ast_only = analyze_ast_only(src, Language::Elixir, "handler");
    assert_has_source_of_type(&ast_only, TaintSourceType::FileRead, "ast_only");
    assert_has_sink_of_type(&ast_only, TaintSinkType::ShellExec, "ast_only");
}

/// Elixir: `cmd = IO.gets("> "); Code.eval_string(cmd)` — UserInput via
/// `IO.gets` -> CodeEval via `Code.eval_string`.
#[test]
fn elixir_user_input_to_code_eval_string_via_compute_taint() {
    let src = "\
def handler do
  cmd = IO.gets(\"> \")
  Code.eval_string(cmd)
end
";
    let regular = analyze_with_ssa(src, Language::Elixir, "handler", false);
    assert_has_source_of_type(&regular, TaintSourceType::UserInput, "regular");
    assert_has_sink_of_type(&regular, TaintSinkType::CodeEval, "regular");
    let ast_only = analyze_ast_only(src, Language::Elixir, "handler");
    assert_has_source_of_type(&ast_only, TaintSourceType::UserInput, "ast_only");
    assert_has_sink_of_type(&ast_only, TaintSinkType::CodeEval, "ast_only");
}

/// Elixir: `cmd = IO.gets("> "); Ecto.Adapters.SQL.query(repo, cmd, [])`
/// — UserInput via `IO.gets` -> SqlQuery via `Ecto.Adapters.SQL.query`
/// (multi-segment dotted receiver). Verifies that the W2-pre call-shape
/// `rfind('.')` split correctly produces `("Ecto.Adapters.SQL", "query")`.
#[test]
fn elixir_user_input_to_ecto_sql_query_via_compute_taint() {
    let src = "\
def handler(repo) do
  cmd = IO.gets(\"> \")
  Ecto.Adapters.SQL.query(repo, cmd, [])
end
";
    let regular = analyze_with_ssa(src, Language::Elixir, "handler", false);
    assert_has_source_of_type(&regular, TaintSourceType::UserInput, "regular");
    assert_has_sink_of_type(&regular, TaintSinkType::SqlQuery, "regular");
    let ast_only = analyze_ast_only(src, Language::Elixir, "handler");
    assert_has_source_of_type(&ast_only, TaintSourceType::UserInput, "ast_only");
    assert_has_sink_of_type(&ast_only, TaintSinkType::SqlQuery, "ast_only");
}

/// Elixir: `IO.gets("> ") |> System.cmd([])` — pipe operator desugars at
/// parse time to `System.cmd(IO.gets("> "), [])`. tree-sitter-elixir
/// represents the pipe as a `binary_operator` whose right side is a `call`,
/// so `walk_descendants` still visits the inner `System.cmd` call. Verifies
/// the pipe doesn't break detection.
#[test]
fn elixir_pipe_operator_io_gets_to_system_cmd_via_compute_taint() {
    let src = "\
def handler do
  IO.gets(\"> \") |> System.cmd([])
end
";
    let regular = analyze_with_ssa(src, Language::Elixir, "handler", false);
    assert_has_source_of_type(&regular, TaintSourceType::UserInput, "regular");
    assert_has_sink_of_type(&regular, TaintSinkType::ShellExec, "regular");
    let ast_only = analyze_ast_only(src, Language::Elixir, "handler");
    assert_has_source_of_type(&ast_only, TaintSourceType::UserInput, "ast_only");
    assert_has_sink_of_type(&ast_only, TaintSinkType::ShellExec, "ast_only");
}

// ===========================================================================
// OCaml (5 fixtures: 4 Module.function + 1 bare-call)
// ===========================================================================

/// OCaml: `let cmd = Sys.getenv "CMD" in Sys.command cmd` — EnvVar via
/// `Sys.getenv` Module call -> ShellExec via `Sys.command` Module call.
/// Both sides require structured matching.
#[test]
fn ocaml_sys_getenv_to_sys_command_via_compute_taint() {
    let src = "\
let handler () =
  let cmd = Sys.getenv \"CMD\" in
  ignore (Sys.command cmd)
";
    let regular = analyze_with_ssa(src, Language::Ocaml, "handler", false);
    assert_has_source_of_type(&regular, TaintSourceType::EnvVar, "regular");
    assert_has_sink_of_type(&regular, TaintSinkType::ShellExec, "regular");
    let ast_only = analyze_ast_only(src, Language::Ocaml, "handler");
    assert_has_source_of_type(&ast_only, TaintSourceType::EnvVar, "ast_only");
    assert_has_sink_of_type(&ast_only, TaintSinkType::ShellExec, "ast_only");
}

/// OCaml: `let cmd = In_channel.read_all path in Sys.command cmd` —
/// FileRead via `In_channel.read_all` Module call -> ShellExec via
/// `Sys.command` Module call.
#[test]
fn ocaml_in_channel_read_all_to_sys_command_via_compute_taint() {
    let src = "\
let handler path =
  let cmd = In_channel.read_all path in
  ignore (Sys.command cmd)
";
    let regular = analyze_with_ssa(src, Language::Ocaml, "handler", false);
    assert_has_source_of_type(&regular, TaintSourceType::FileRead, "regular");
    assert_has_sink_of_type(&regular, TaintSinkType::ShellExec, "regular");
    let ast_only = analyze_ast_only(src, Language::Ocaml, "handler");
    assert_has_source_of_type(&ast_only, TaintSourceType::FileRead, "ast_only");
    assert_has_sink_of_type(&ast_only, TaintSinkType::ShellExec, "ast_only");
}

/// OCaml: `let cmd = In_channel.input_all ic in Unix.execvp cmd [||]` —
/// FileRead via `In_channel.input_all` -> ShellExec via `Unix.execvp`.
#[test]
fn ocaml_in_channel_input_all_to_unix_execvp_via_compute_taint() {
    let src = "\
let handler ic =
  let cmd = In_channel.input_all ic in
  Unix.execvp cmd [||]
";
    let regular = analyze_with_ssa(src, Language::Ocaml, "handler", false);
    assert_has_source_of_type(&regular, TaintSourceType::FileRead, "regular");
    assert_has_sink_of_type(&regular, TaintSinkType::ShellExec, "regular");
    let ast_only = analyze_ast_only(src, Language::Ocaml, "handler");
    assert_has_source_of_type(&ast_only, TaintSourceType::FileRead, "ast_only");
    assert_has_sink_of_type(&ast_only, TaintSinkType::ShellExec, "ast_only");
}

/// OCaml: `let cmd = read_line () in Sys.command cmd` — UserInput via the
/// bare-call `read_line` (already AST-native via `OCAML_AST_SOURCES`
/// `call_names: ["read_line"]`) -> ShellExec via `Sys.command` Module call.
///
/// This test is NOT one of the 6 OCaml Module.function rewrites — the
/// `read_line` source side is AST-native at HEAD. Only the `Sys.command`
/// sink side requires M4 to land for `analyze_ast_only` to PASS. Listed in
/// dispatch-contract M1 because it pairs the bare-call source with a
/// Module.function sink.
#[test]
fn ocaml_read_line_to_sys_command_via_compute_taint() {
    let src = "\
let handler () =
  let cmd = read_line () in
  ignore (Sys.command cmd)
";
    let regular = analyze_with_ssa(src, Language::Ocaml, "handler", false);
    assert_has_source_of_type(&regular, TaintSourceType::UserInput, "regular");
    assert_has_sink_of_type(&regular, TaintSinkType::ShellExec, "regular");
    let ast_only = analyze_ast_only(src, Language::Ocaml, "handler");
    // Source side already AST-native; fails on sink side at HEAD pre-M4.
    assert_has_source_of_type(&ast_only, TaintSourceType::UserInput, "ast_only");
    assert_has_sink_of_type(&ast_only, TaintSinkType::ShellExec, "ast_only");
}

/// OCaml: `let cmd = read_line () in Sqlite3.exec db cmd` — UserInput via
/// bare-call `read_line` -> SqlQuery via `Sqlite3.exec` Module call.
#[test]
fn ocaml_user_input_to_sqlite3_exec_via_compute_taint() {
    let src = "\
let handler db =
  let cmd = read_line () in
  ignore (Sqlite3.exec db cmd)
";
    let regular = analyze_with_ssa(src, Language::Ocaml, "handler", false);
    assert_has_source_of_type(&regular, TaintSourceType::UserInput, "regular");
    assert_has_sink_of_type(&regular, TaintSinkType::SqlQuery, "regular");
    let ast_only = analyze_ast_only(src, Language::Ocaml, "handler");
    assert_has_source_of_type(&ast_only, TaintSourceType::UserInput, "ast_only");
    assert_has_sink_of_type(&ast_only, TaintSinkType::SqlQuery, "ast_only");
}

// ===========================================================================
// String-literal regression guards (3 fixtures — must PASS on BOTH paths)
// ===========================================================================
//
// These assert ZERO findings on fixtures where the dangerous Module.function
// name appears ONLY inside a string literal — never as a real call. They are
// the closes-#24 generalization to Ruby/Elixir/OCaml. Must stay GREEN
// through M5 (when the regex banks are deleted).

/// Ruby: `msg = "do not run IO.popen here"; puts msg` — `IO.popen`
/// substring in a string literal must not produce any source/sink.
#[test]
fn ruby_string_literal_io_popen_substring_zero_findings() {
    let src = "\
def handler
    msg = \"do not run IO.popen here\"
    puts msg
end
";
    let regular = analyze_with_ssa(src, Language::Ruby, "handler", false);
    assert!(
        regular.sources.is_empty(),
        "[regular] expected ZERO sources for string-literal IO.popen substring; got sources={:?}",
        regular.sources
    );
    assert!(
        !regular.sinks.iter().any(|s| matches!(s.sink_type, TaintSinkType::ShellExec)),
        "[regular] expected ZERO ShellExec sinks for string-literal IO.popen substring; got sinks={:?}",
        regular.sinks
    );
    let ast_only = analyze_ast_only(src, Language::Ruby, "handler");
    assert!(
        ast_only.sources.is_empty(),
        "[ast_only] expected ZERO sources for string-literal IO.popen substring; got sources={:?}",
        ast_only.sources
    );
    assert!(
        !ast_only.sinks.iter().any(|s| matches!(s.sink_type, TaintSinkType::ShellExec)),
        "[ast_only] expected ZERO ShellExec sinks for string-literal IO.popen substring; got sinks={:?}",
        ast_only.sinks
    );
}

/// Elixir: `msg = "System.cmd is dangerous"; IO.puts(msg)` — `System.cmd`
/// substring in a string literal must not produce any sink. (Note:
/// `IO.puts` itself is not a registered Elixir source — used here purely
/// to exercise the parser. The fixture's purpose is verifying the
/// `System.cmd` substring is NOT picked up.)
#[test]
fn elixir_string_literal_system_cmd_substring_zero_findings() {
    let src = "\
def handler do
  msg = \"System.cmd is dangerous\"
  IO.puts(msg)
end
";
    let regular = analyze_with_ssa(src, Language::Elixir, "handler", false);
    assert!(
        !regular.sinks.iter().any(|s| matches!(s.sink_type, TaintSinkType::ShellExec)),
        "[regular] expected ZERO ShellExec sinks for string-literal System.cmd substring; got sinks={:?}",
        regular.sinks
    );
    let ast_only = analyze_ast_only(src, Language::Elixir, "handler");
    assert!(
        !ast_only.sinks.iter().any(|s| matches!(s.sink_type, TaintSinkType::ShellExec)),
        "[ast_only] expected ZERO ShellExec sinks for string-literal System.cmd substring; got sinks={:?}",
        ast_only.sinks
    );
}

/// OCaml: `let msg = "Sys.command is dangerous" in print_endline msg` —
/// `Sys.command` substring in a string literal must not produce any sink.
#[test]
fn ocaml_string_literal_sys_command_substring_zero_findings() {
    let src = "\
let handler () =
  let msg = \"Sys.command is dangerous\" in
  print_endline msg
";
    let regular = analyze_with_ssa(src, Language::Ocaml, "handler", false);
    assert!(
        !regular.sinks.iter().any(|s| matches!(s.sink_type, TaintSinkType::ShellExec)),
        "[regular] expected ZERO ShellExec sinks for string-literal Sys.command substring; got sinks={:?}",
        regular.sinks
    );
    let ast_only = analyze_ast_only(src, Language::Ocaml, "handler");
    assert!(
        !ast_only.sinks.iter().any(|s| matches!(s.sink_type, TaintSinkType::ShellExec)),
        "[ast_only] expected ZERO ShellExec sinks for string-literal Sys.command substring; got sinks={:?}",
        ast_only.sinks
    );
}
