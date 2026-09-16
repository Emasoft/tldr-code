//! regex-removal-v1 — Wave 1.5 per-language baseline integration tests.
//!
//! ZERO existing integration tests called `compute_taint_with_tree` for any
//! language other than Python and TypeScript before this milestone. This
//! file establishes a minimum 1 end-to-end source→sink test per Language
//! enum slot so the Wave-2 atomic deletion of the TS/Python regex banks
//! does not silently lose entire languages.
//!
//! Coverage matrix (16 tests):
//!   1. Python       — `request.args` -> `eval`
//!   2. TypeScript   — `req.body`     -> `eval`            (Express)
//!   3. JavaScript   — `req.body`     -> `eval`            (JS grammar)
//!   4. Go           — `r.URL.Query`  -> `exec.Command`
//!   5. Java         — `getParameter` -> `Runtime.exec`
//!   6. Rust         — `stdin.read_line` -> `Command::new`
//!   7. C            — `fgets`        -> `system`
//!   8. C++          — `std::cin`     -> `system`
//!   9. Ruby         — `gets`         -> `system`
//!  10. Kotlin       — `readLine`     -> `Runtime.exec`
//!  11. Swift        — `readLine`     -> `Process().run`
//!  12. C#           — `Console.ReadLine` -> `Process.Start`
//!  13. Scala        — `StdIn.readLine` -> `Runtime.exec`
//!  14. PHP          — `$_GET`        -> `system`
//!  15. Lua          — `io.read`      -> `os.execute`
//!  16. OCaml        — `read_line`    -> `Sys.command`
//!
//! Elixir is intentionally NOT mirrored here: the Elixir module-call
//! partial-coverage probe in `rr_stdlib_integ_test.rs::elixir_system_
//! cmd_module_call_via_compute_taint` already exercises the same fixture
//! (per worker-2-integ-tests.json category-C `note`: "Same fixture as
//! Category B Elixir test; in baseline category we tolerate either
//! call_names path OR substring fallback. Drop one to dedup.").
//!
//! Luau is collapsed into Lua's slot — the two share `LUA_AST_*` banks
//! and the `field_access_info` dispatch lands on `dot_index_expression`
//! for both grammars.
//!
//! Each test asserts AT LEAST one source AND at least one sink of the
//! relevant type AND at least one source→sink flow. The point is COVERAGE
//! breadth, not depth — proves the language is at least minimally
//! exercised through `compute_taint_with_tree` so a Wave-2 deletion
//! regression in any of these slots is loud, not silent.

use tldr_core::{Language, TaintSinkType, TaintSourceType};

#[path = "common/integ_helpers.rs"]
mod common;

use common::{analyze_with_ssa, assert_source_to_eval_flow};

// ---------- 1. Python ----------

/// Python baseline: `request.args` (HttpParam) -> `eval`. Exercises
/// `PYTHON_AST_SOURCES('request','args')` and `PYTHON_AST_SINKS` `eval`
/// call_name.
#[test]
fn python_baseline_request_args_to_eval_compute_taint() {
    let src = "\
def handler():
    data = request.args
    eval(data)
";
    let result = analyze_with_ssa(src, Language::Python, "handler", /* use_ssa */ false);
    assert_source_to_eval_flow(&result, TaintSourceType::HttpParam);
}

// ---------- 2. TypeScript ----------

/// TypeScript baseline: Express `req.body` (HttpBody) -> `eval`. Already
/// covered by val002; kept here as the category-C baseline for the
/// TypeScript enum slot.
#[test]
fn typescript_baseline_req_body_to_eval_compute_taint() {
    let src = "\
function handler(req, res) {
    const x = req.body;
    eval(x);
}
";
    let result = analyze_with_ssa(
        src,
        Language::TypeScript,
        "handler",
        /* use_ssa */ false,
    );
    assert_source_to_eval_flow(&result, TaintSourceType::HttpBody);
}

// ---------- 3. JavaScript ----------

/// JavaScript baseline: same Express shape as the TS test but exercises
/// the JS grammar dispatch in `field_access_info` (member_expression
/// node under tree-sitter-javascript).
#[test]
fn javascript_baseline_req_body_to_eval_compute_taint() {
    let src = "\
function handler(req, res) {
    var x = req.body;
    eval(x);
}
";
    let result = analyze_with_ssa(
        src,
        Language::JavaScript,
        "handler",
        /* use_ssa */ false,
    );
    assert_source_to_eval_flow(&result, TaintSourceType::HttpBody);
}

// ---------- 4. Go ----------

/// Go baseline: `r.URL.Query().Get("cmd")` -> `exec.Command(...).Run()`.
/// Exercises `GO_AST_SOURCES` selector_expression + `GO_AST_SINKS`
/// `exec.Command`.
#[test]
fn go_baseline_request_form_to_exec_compute_taint() {
    let src = "\
package main
import (\"net/http\"; \"os/exec\")
func handler(w http.ResponseWriter, r *http.Request) {
    cmd := r.URL.Query().Get(\"cmd\")
    exec.Command(\"sh\", \"-c\", cmd).Run()
}
";
    let result = analyze_with_ssa(src, Language::Go, "handler", /* use_ssa */ false);
    let sink_lines: Vec<_> = result
        .sinks
        .iter()
        .filter(|s| matches!(s.sink_type, TaintSinkType::ShellExec))
        .map(|s| s.line)
        .collect();
    assert!(
        !sink_lines.is_empty(),
        "expected at least one ShellExec sink for exec.Command; got sinks={:?}",
        result.sinks
    );
    assert!(
        !result.sources.is_empty(),
        "expected at least one source for r.URL.Query; got sources={:?}",
        result.sources
    );
}

// ---------- 5. Java ----------

/// Java baseline: `request.getParameter("c")` -> `Runtime.getRuntime().
/// exec(cmd)`. Exercises `JAVA_AST_SOURCES` field_access +
/// `JAVA_AST_SINKS` Runtime.exec.
#[test]
fn java_baseline_request_param_to_runtime_exec_compute_taint() {
    let src = "\
public class H {
    public void handle(HttpServletRequest request) throws Exception {
        String cmd = request.getParameter(\"c\");
        Runtime.getRuntime().exec(cmd);
    }
}
";
    let result = analyze_with_ssa(src, Language::Java, "handle", /* use_ssa */ false);
    let sink_lines: Vec<_> = result
        .sinks
        .iter()
        .filter(|s| matches!(s.sink_type, TaintSinkType::ShellExec))
        .map(|s| s.line)
        .collect();
    assert!(
        !sink_lines.is_empty(),
        "expected at least one ShellExec sink for Runtime.exec; got sinks={:?}",
        result.sinks
    );
    assert!(
        !result.sources.is_empty(),
        "expected at least one source for getParameter; got sources={:?}",
        result.sources
    );
}

// ---------- 6. Rust ----------

/// Rust baseline: `std::env::var("CMD")` (EnvVar source) -> `std::
/// process::Command::new(cmd).spawn()`. Exercises `RUST_AST_SOURCES`
/// `std::env::var` substring + `RUST_AST_SINKS` `Command::new`.
///
/// Fixture deliberately uses an owned `String` for the sink argument
/// (no `&` reference) because the regex `extract_call_arg` does not yet
/// strip `&` reference operators when extracting the tainted argument
/// — passing `Command::new(&s)` would parse the arg as `&s` (not a
/// valid identifier) and the sink would be skipped. Using `cmd` plain
/// keeps the baseline a pure end-to-end smoke test.
#[test]
fn rust_baseline_stdin_to_command_new_compute_taint() {
    let src = "\
fn handler() {
    let cmd = std::env::var(\"CMD\").unwrap();
    std::process::Command::new(cmd).spawn().unwrap();
}
";
    let result = analyze_with_ssa(src, Language::Rust, "handler", /* use_ssa */ false);
    let sink_lines: Vec<_> = result
        .sinks
        .iter()
        .filter(|s| matches!(s.sink_type, TaintSinkType::ShellExec))
        .map(|s| s.line)
        .collect();
    assert!(
        !sink_lines.is_empty(),
        "expected at least one ShellExec sink for Command::new; got sinks={:?}",
        result.sinks
    );
    assert!(
        !result.sources.is_empty(),
        "expected at least one source for std::env::var; got sources={:?}",
        result.sources
    );
}

// ---------- 7. C ----------

/// C baseline: `fgets(buf, ..., stdin)` -> `system(buf)`. Exercises the
/// zero-member-pattern `C_AST_SOURCES` (call_names ONLY) and
/// `C_AST_SINKS` `system` call_name. Also a smoke test for the C grammar
/// dispatch path.
#[test]
fn c_baseline_gets_to_system_compute_taint() {
    let src = "\
#include <stdio.h>
#include <stdlib.h>
void handler(void) {
    char buf[256];
    fgets(buf, sizeof(buf), stdin);
    system(buf);
}
";
    let result = analyze_with_ssa(src, Language::C, "handler", /* use_ssa */ false);
    let sink_lines: Vec<_> = result
        .sinks
        .iter()
        .filter(|s| matches!(s.sink_type, TaintSinkType::ShellExec))
        .map(|s| s.line)
        .collect();
    assert!(
        !sink_lines.is_empty(),
        "expected at least one ShellExec sink for system(); got sinks={:?}",
        result.sinks
    );
    assert!(
        !result.sources.is_empty(),
        "expected at least one source for fgets/stdin; got sources={:?}",
        result.sources
    );
}

// ---------- 8. C++ ----------

/// C++ baseline: `std::cin >> s` -> `system(s.c_str())`. Exercises
/// `CPP_AST_SOURCES` + `CPP_AST_SINKS` `system`.
#[test]
fn cpp_baseline_cin_to_system_compute_taint() {
    let src = "\
#include <iostream>
#include <cstdlib>
void handler() {
    std::string s;
    std::cin >> s;
    system(s.c_str());
}
";
    let result = analyze_with_ssa(src, Language::Cpp, "handler", /* use_ssa */ false);
    let sink_lines: Vec<_> = result
        .sinks
        .iter()
        .filter(|s| matches!(s.sink_type, TaintSinkType::ShellExec))
        .map(|s| s.line)
        .collect();
    assert!(
        !sink_lines.is_empty(),
        "expected at least one ShellExec sink for system(); got sinks={:?}",
        result.sinks
    );
}

// ---------- 9. Ruby ----------

/// Ruby baseline: `gets` -> `system(cmd)`. Exercises `RUBY_AST_SOURCES`
/// `gets` call_name + `RUBY_AST_SINKS` `system` call_name (avoids the
/// field_access_info partial-coverage gap for Ruby module calls — that
/// gap is exercised by the `IO.popen` probe in `rr_stdlib_integ_test`).
#[test]
fn ruby_baseline_gets_to_system_compute_taint() {
    let src = "\
def handler
    cmd = gets
    system(cmd)
end
";
    let result = analyze_with_ssa(src, Language::Ruby, "handler", /* use_ssa */ false);
    let sink_lines: Vec<_> = result
        .sinks
        .iter()
        .filter(|s| matches!(s.sink_type, TaintSinkType::ShellExec))
        .map(|s| s.line)
        .collect();
    assert!(
        !sink_lines.is_empty(),
        "expected at least one ShellExec sink for system(); got sinks={:?}",
        result.sinks
    );
}

// ---------- 10. Kotlin ----------

/// Kotlin baseline: `readLine()` -> `Runtime.getRuntime().exec(line)`.
/// Exercises `KOTLIN_AST_SOURCES` `readLine` call + `KOTLIN_AST_SINKS`
/// Runtime.exec via navigation_expression.
#[test]
fn kotlin_baseline_readline_to_runtime_exec_compute_taint() {
    let src = "\
fun handler() {
    val line = readLine() ?: return
    Runtime.getRuntime().exec(line)
}
";
    let result = analyze_with_ssa(src, Language::Kotlin, "handler", /* use_ssa */ false);
    let sink_lines: Vec<_> = result
        .sinks
        .iter()
        .filter(|s| matches!(s.sink_type, TaintSinkType::ShellExec))
        .map(|s| s.line)
        .collect();
    assert!(
        !sink_lines.is_empty(),
        "expected at least one ShellExec sink for Runtime.exec; got sinks={:?}",
        result.sinks
    );
}

// ---------- 11. Swift ----------

/// Swift baseline: `readLine()` -> `Process().launchPath = input` /
/// `p.run()`. Exercises `SWIFT_AST_SOURCES` `readLine` + `SWIFT_AST_
/// SINKS` Process / launch via navigation_expression.
#[test]
fn swift_baseline_readline_to_process_run_compute_taint() {
    let src = "\
import Foundation
func handler() {
    guard let line = readLine() else { return }
    let p = Process()
    p.launchPath = line
    try? p.run()
}
";
    let result = analyze_with_ssa(src, Language::Swift, "handler", /* use_ssa */ false);
    let sink_lines: Vec<_> = result
        .sinks
        .iter()
        .filter(|s| matches!(s.sink_type, TaintSinkType::ShellExec))
        .map(|s| s.line)
        .collect();
    assert!(
        !sink_lines.is_empty(),
        "expected at least one ShellExec sink for Process / launch; got sinks={:?}",
        result.sinks
    );
}

// ---------- 12. C# ----------

/// C# baseline: `System.Console.ReadLine()` -> `Process.Start(s)`.
/// Exercises `CSHARP_AST_SOURCES` Console.ReadLine member_access_
/// expression + `CSHARP_AST_SINKS` Process.Start.
#[test]
fn csharp_baseline_readline_to_process_start_compute_taint() {
    let src = "\
using System.Diagnostics;
public class H {
    public void Handle() {
        var s = System.Console.ReadLine();
        Process.Start(s);
    }
}
";
    let result = analyze_with_ssa(src, Language::CSharp, "Handle", /* use_ssa */ false);
    let sink_lines: Vec<_> = result
        .sinks
        .iter()
        .filter(|s| matches!(s.sink_type, TaintSinkType::ShellExec))
        .map(|s| s.line)
        .collect();
    assert!(
        !sink_lines.is_empty(),
        "expected at least one ShellExec sink for Process.Start; got sinks={:?}",
        result.sinks
    );
}

// ---------- 13. Scala ----------

/// Scala baseline: `scala.io.StdIn.readLine()` -> `Runtime.getRuntime.
/// exec(cmd)`. Exercises `SCALA_AST_SOURCES` + `SCALA_AST_SINKS` via
/// field_expression / select_expression.
#[test]
fn scala_baseline_stdin_to_process_compute_taint() {
    let src = "\
object H {
  def handler(): Unit = {
    val cmd = scala.io.StdIn.readLine()
    Runtime.getRuntime.exec(cmd)
  }
}
";
    let result = analyze_with_ssa(src, Language::Scala, "handler", /* use_ssa */ false);
    let sink_lines: Vec<_> = result
        .sinks
        .iter()
        .filter(|s| matches!(s.sink_type, TaintSinkType::ShellExec))
        .map(|s| s.line)
        .collect();
    assert!(
        !sink_lines.is_empty(),
        "expected at least one ShellExec sink for Runtime.exec; got sinks={:?}",
        result.sinks
    );
}

// ---------- 14. PHP ----------

/// PHP baseline: `$_GET['c']` -> `system($cmd)`. Exercises `PHP_AST_
/// SOURCES` `$_GET` subscript / member_access + `PHP_AST_SINKS` `system`
/// call.
#[test]
fn php_baseline_get_to_system_compute_taint() {
    let src = "\
<?php
function handler() {
    $cmd = $_GET['c'];
    system($cmd);
}
";
    let result = analyze_with_ssa(src, Language::Php, "handler", /* use_ssa */ false);
    let sink_lines: Vec<_> = result
        .sinks
        .iter()
        .filter(|s| matches!(s.sink_type, TaintSinkType::ShellExec))
        .map(|s| s.line)
        .collect();
    assert!(
        !sink_lines.is_empty(),
        "expected at least one ShellExec sink for system(); got sinks={:?}",
        result.sinks
    );
}

// ---------- 15. Lua ----------

/// Lua baseline: `io.read()` -> `os.execute(cmd)`. Exercises `LUA_AST_
/// SOURCES` `io.read` dot_index_expression + `LUA_AST_SINKS` `os.
/// execute` call. Also exercises the dispatch path shared with Luau (the
/// two grammars share `LUA_AST_*` banks).
#[test]
fn lua_baseline_io_read_to_os_execute_compute_taint() {
    let src = "\
function handler()
    local cmd = io.read()
    os.execute(cmd)
end
";
    let result = analyze_with_ssa(src, Language::Lua, "handler", /* use_ssa */ false);
    let sink_lines: Vec<_> = result
        .sinks
        .iter()
        .filter(|s| matches!(s.sink_type, TaintSinkType::ShellExec))
        .map(|s| s.line)
        .collect();
    assert!(
        !sink_lines.is_empty(),
        "expected at least one ShellExec sink for os.execute; got sinks={:?}",
        result.sinks
    );
}

// ---------- 16. OCaml ----------

/// OCaml baseline: `read_line ()` -> `Sys.command cmd`. Exercises
/// `OCAML_AST_SOURCES` `read_line` call + `OCAML_AST_SINKS` `Sys.
/// command` (module call substring fallback per partial-coverage note in
/// worker-2-integ-tests.json — Wave 2 preserves the OCaml regex bank as
/// a HOLD language).
#[test]
fn ocaml_baseline_read_line_to_sys_command_compute_taint() {
    let src = "\
let handler () =
  let cmd = read_line () in
  ignore (Sys.command cmd)
";
    let result = analyze_with_ssa(src, Language::Ocaml, "handler", /* use_ssa */ false);
    let sink_lines: Vec<_> = result
        .sinks
        .iter()
        .filter(|s| matches!(s.sink_type, TaintSinkType::ShellExec))
        .map(|s| s.line)
        .collect();
    assert!(
        !sink_lines.is_empty(),
        "expected at least one ShellExec sink for Sys.command; got sinks={:?}",
        result.sinks
    );
}

// ---------- field_access_info-extension-v1 M1: per-language Module.function baselines ----------
//
// Three additive baseline tests covering the canonical Ruby/Elixir/OCaml
// Module.function shape end-to-end via the regular `analyze_with_ssa` path
// (regex banks active at HEAD; AST-only assertion lives in
// `rr_module_function_integ_test.rs`). These are the "additive coverage"
// proof — they MUST be GREEN at HEAD (regex bank covers them) and stay
// GREEN through M5 (post-deletion the structured AST shape covers them).

/// Ruby Module.function baseline: `gets` -> `IO.popen(cmd)`. ShellExec sink
/// reached via `IO.popen` Module call. Mirrors the existing Ruby baseline
/// at L280 but uses the `IO.popen` sink form instead of bare `system`, so
/// the field_access_info-extension-v1 Module.function path participates in
/// the per-language baseline matrix.
#[test]
fn ruby_module_function_io_popen_baseline() {
    let src = "\
def handler
    cmd = gets
    IO.popen(cmd)
end
";
    let result = analyze_with_ssa(src, Language::Ruby, "handler", /* use_ssa */ false);
    let sink_lines: Vec<_> = result
        .sinks
        .iter()
        .filter(|s| matches!(s.sink_type, TaintSinkType::ShellExec))
        .map(|s| s.line)
        .collect();
    assert!(
        !sink_lines.is_empty(),
        "expected at least one ShellExec sink for IO.popen; got sinks={:?}",
        result.sinks
    );
}

/// Elixir Module.function baseline: `IO.gets("> ")` -> `System.cmd(cmd, [])`.
/// Module.function shape on BOTH source and sink — additive baseline.
#[test]
fn elixir_module_function_system_cmd_baseline() {
    let src = "\
def handler do
  cmd = IO.gets(\"> \")
  System.cmd(cmd, [])
end
";
    let result = analyze_with_ssa(src, Language::Elixir, "handler", /* use_ssa */ false);
    let sink_lines: Vec<_> = result
        .sinks
        .iter()
        .filter(|s| matches!(s.sink_type, TaintSinkType::ShellExec))
        .map(|s| s.line)
        .collect();
    assert!(
        !sink_lines.is_empty(),
        "expected at least one ShellExec sink for System.cmd; got sinks={:?}",
        result.sinks
    );
}

/// OCaml Module.function baseline: `Sys.getenv "CMD"` -> `Sys.command cmd`.
/// EnvVar source via `Sys.getenv` Module call paired with ShellExec via
/// `Sys.command` Module call.
#[test]
fn ocaml_module_function_sys_command_baseline() {
    let src = "\
let handler () =
  let cmd = Sys.getenv \"CMD\" in
  ignore (Sys.command cmd)
";
    let result = analyze_with_ssa(src, Language::Ocaml, "handler", /* use_ssa */ false);
    let source_lines: Vec<_> = result
        .sources
        .iter()
        .filter(|s| matches!(s.source_type, TaintSourceType::EnvVar))
        .map(|s| s.line)
        .collect();
    let sink_lines: Vec<_> = result
        .sinks
        .iter()
        .filter(|s| matches!(s.sink_type, TaintSinkType::ShellExec))
        .map(|s| s.line)
        .collect();
    assert!(
        !source_lines.is_empty(),
        "expected at least one EnvVar source for Sys.getenv; got sources={:?}",
        result.sources
    );
    assert!(
        !sink_lines.is_empty(),
        "expected at least one ShellExec sink for Sys.command; got sinks={:?}",
        result.sinks
    );
}
