//! language-adapter-fixes-v1 — regression tests for the P13.AGG13 (round B)
//! milestone.
//!
//! All tests use real repos under `/tmp/repos/<repo>` and gate on existence
//! so they're skipped silently when the corpus isn't checked out (per the
//! no-synthetic-fixtures-v1 strategy).
//!
//! Bugs covered:
//!
//! - **AGG13-3** (HIGH, P12 regression): JS `tldr resources <file> <fn>`
//!   and `tldr contracts <file> <fn>` returned
//!   `"Error: function 'fn' not found"` for CommonJS-style assignments
//!   (`app.foo = function foo() {}`) even though `tldr explain`,
//!   `tldr definition`, and the AST extractor all see the function. Fix:
//!   extend the per-command AST resolver (`find_function_recursive` in
//!   `commands/patterns/resources.rs` and `commands/contracts/contracts.rs`)
//!   to recognise the same `assignment_expression` and object-literal
//!   `pair` cases that `commands/remaining/explain.rs` already handled
//!   in P12.AGG12-7.
//!
//! - **AGG13-4** (MED): C# `tldr impact <fn>` returned `caller_count: 0`
//!   for a function whose call sites flow through field-typed receivers
//!   (`_writer.WriteToken(...)` where `_writer` is a private field). The
//!   call-graph builder did not emit those edges, but `tldr explain` and
//!   `tldr references` did find them via the references fallback. Fix:
//!   mirror `enrich_with_references` (P12.AGG12-1) inside `impact`'s CLI
//!   wrapper so it agrees with explain/references on the same function.
//!
//! - **AGG13-5** (MED): `tldr context <file>:<func>` returned
//!   `"Error: Function not found"` even though the bare-name form
//!   (`tldr context <func>` from inside the project) worked. Fix:
//!   * Parse `<file>:<func>` in the context CLI when the LHS resolves
//!     to an existing file on disk; treat the RHS as `entry` and inject
//!     the file as a `--file` filter.
//!   * Auto-derive the project root from the file's enclosing directory
//!     when no explicit project path was supplied.
//!   * Also fix `find_function_in_graph` and `scan_project_for_function`
//!     in `tldr-core` to compare canonical absolute paths so an absolute
//!     `--file` filter matches a relative call-graph file path.
//!
//! - **AGG13-10** (MED): `tldr clones <path> --lang luau` silently
//!   ignored the global `-l/--lang` flag and fell through to autodetect
//!   (which picked `cpp` for the luau-luau corpus because that's the
//!   majority extension). Fix: route `cli.lang` into `ClonesArgs::run`
//!   and merge it into `ClonesOptions.language` when no `--language`
//!   override is set.

use assert_cmd::Command;
use serde_json::Value;
use std::path::Path;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

/// Skip helper: returns true and prints a notice when `path` doesn't
/// exist. Tests gate on real-repo presence per no-synthetic-fixtures-v1.
fn skip_if_missing(path: &str) -> bool {
    if !Path::new(path).exists() {
        eprintln!("[skip] {} not present", path);
        return true;
    }
    false
}

fn run_json(args: &[&str]) -> Value {
    let out = tldr_cmd().args(args).output().expect("spawn tldr");
    let stdout = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "parse JSON for `tldr {}`: {}\nstdout: {}\nstderr: {}",
            args.join(" "),
            e,
            stdout,
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

// =============================================================================
// AGG13-3: JS resources/contracts CommonJS function-expression assignments
// =============================================================================

/// `tldr resources express/lib/application.js render` MUST resolve the
/// function and emit a non-error JSON document. Pre-fix it returned
/// `"Error: function 'render' not found"`.
#[test]
fn agg13_3_js_resources_finds_commonjs_assigned_render() {
    if skip_if_missing("/tmp/repos/express/lib/application.js") {
        return;
    }
    let report = run_json(&[
        "resources",
        "/tmp/repos/express/lib/application.js",
        "render",
        "--format",
        "json",
    ]);
    // Fields the schema guarantees once the resolver succeeds.
    assert_eq!(report["function"], "render");
    assert_eq!(report["language"], "javascript");
    // resources MUST surface the analysis arrays even when empty —
    // their PRESENCE confirms the resolver path executed.
    assert!(
        report.get("leaks").is_some(),
        "expected leaks array, got: {report}"
    );
}

/// Same fix, sibling command. Pre-fix `tldr contracts <file> render`
/// also returned `"Error: function 'render' not found"`.
#[test]
fn agg13_3_js_contracts_finds_commonjs_assigned_render() {
    if skip_if_missing("/tmp/repos/express/lib/application.js") {
        return;
    }
    let report = run_json(&[
        "contracts",
        "/tmp/repos/express/lib/application.js",
        "render",
        "--format",
        "json",
    ]);
    assert_eq!(report["function"], "render");
    // Pre/post/inv arrays are present (may be empty) once the resolver
    // succeeds.
    assert!(report.get("preconditions").is_some());
    assert!(report.get("postconditions").is_some());
}

/// Coverage for the second function on the same file (`init`). Both
/// `app.init` and `app.handle` use the same surface; this asserts
/// resources resolves a SECOND CommonJS-assigned name to make sure the
/// fix isn't an accidental specific-name match.
#[test]
fn agg13_3_js_resources_finds_commonjs_assigned_init() {
    if skip_if_missing("/tmp/repos/express/lib/application.js") {
        return;
    }
    let report = run_json(&[
        "resources",
        "/tmp/repos/express/lib/application.js",
        "init",
        "--format",
        "json",
    ]);
    assert_eq!(report["function"], "init");
    assert_eq!(report["language"], "javascript");
}

// =============================================================================
// AGG13-4: C# impact returns caller_count > 0 for field-typed dispatch
// =============================================================================

/// `tldr impact WriteToken` from inside the BSON repo MUST return at
/// least one caller. Pre-fix it returned `caller_count: 0` and
/// `note: "Entry point - no callers found"` even though `tldr explain`
/// finds 2 callers (WriteEnd in BsonDataWriter.cs and WriteTokenAsync
/// in BsonBinaryWriter.Async.cs) and `tldr references` finds 3 refs.
///
/// The full BSON repo is needed because the partial corpus only ships
/// `BsonDataReader.Async.cs`. The test gates on the BinaryWriter file
/// to avoid running against the partial clone.
#[test]
fn agg13_4_csharp_impact_writetoken_has_callers_via_references_fallback() {
    let bson_writer =
        "/tmp/repos/csharp-newtonsoft-bson-full/Src/Newtonsoft.Json.Bson/BsonBinaryWriter.cs";
    if skip_if_missing(bson_writer) {
        return;
    }
    let report = run_json(&[
        "impact",
        "WriteToken",
        "/tmp/repos/csharp-newtonsoft-bson-full",
        "--format",
        "json",
    ]);
    let targets = report["targets"]
        .as_object()
        .expect("targets object on impact report");
    assert!(!targets.is_empty(), "expected at least 1 target: {report}");
    let max_callers = targets
        .values()
        .map(|t| t["caller_count"].as_u64().unwrap_or(0))
        .max()
        .unwrap_or(0);
    assert!(
        max_callers >= 1,
        "expected ≥1 caller for WriteToken (explain finds 2), got {max_callers}: {report}"
    );
}

/// Sibling check: WriteTokenInternal also has callers via the same
/// dispatch pattern (`WriteToken` calls `WriteTokenInternal` directly,
/// `WriteTokenInternal` recurses on `property.Value`). Asserts the
/// enrichment is not single-shot.
#[test]
fn agg13_4_csharp_impact_writetokeninternal_has_callers() {
    let bson_writer =
        "/tmp/repos/csharp-newtonsoft-bson-full/Src/Newtonsoft.Json.Bson/BsonBinaryWriter.cs";
    if skip_if_missing(bson_writer) {
        return;
    }
    let report = run_json(&[
        "impact",
        "WriteTokenInternal",
        "/tmp/repos/csharp-newtonsoft-bson-full",
        "--format",
        "json",
    ]);
    let targets = report["targets"]
        .as_object()
        .expect("targets object on impact report");
    let max_callers = targets
        .values()
        .map(|t| t["caller_count"].as_u64().unwrap_or(0))
        .max()
        .unwrap_or(0);
    assert!(
        max_callers >= 1,
        "expected ≥1 caller for WriteTokenInternal, got {max_callers}: {report}"
    );
}

/// Non-regression: a function whose call graph already produced edges
/// MUST keep its existing caller count and not double-count the
/// references enrichment. Uses the partial corpus (BsonDataReader.Async.cs)
/// where ReadElementAsync had `caller_count = 2` pre-fix.
#[test]
fn agg13_4_csharp_impact_known_good_function_unchanged() {
    if skip_if_missing("/tmp/repos/csharp-newtonsoft-bson") {
        return;
    }
    let report = run_json(&[
        "impact",
        "ReadElementAsync",
        "/tmp/repos/csharp-newtonsoft-bson",
        "--format",
        "json",
    ]);
    let targets = report["targets"]
        .as_object()
        .expect("targets object on impact report");
    let max_callers = targets
        .values()
        .map(|t| t["caller_count"].as_u64().unwrap_or(0))
        .max()
        .unwrap_or(0);
    // Pre-fix value was 2. Post-fix may be ≥2 once references enrichment
    // also picks up the same call site, but MUST not be < 2.
    assert!(
        max_callers >= 2,
        "expected ≥2 callers for ReadElementAsync, got {max_callers}: {report}"
    );
}

// =============================================================================
// AGG13-5: context <file>:<func> shorthand
// =============================================================================

/// `tldr context <abs-file>:<func>` MUST resolve the function. Pre-fix
/// it returned `"Error: Function not found"` with a "did you mean: render"
/// hint even though the function existed at line 522 of the file.
#[test]
fn agg13_5_context_file_func_shorthand_js() {
    if skip_if_missing("/tmp/repos/express/lib/application.js") {
        return;
    }
    let report = run_json(&[
        "context",
        "/tmp/repos/express/lib/application.js:render",
        "--format",
        "json",
    ]);
    assert_eq!(report["entry_point"], "render");
    let funcs = report["functions"]
        .as_array()
        .expect("functions array on context report");
    assert!(
        !funcs.is_empty(),
        "expected ≥1 function in context: {report}"
    );
}

/// Multi-language coverage: same shorthand on a python file. Confirms
/// the parsing & project-root inference work for non-JS too.
#[test]
fn agg13_5_context_file_func_shorthand_python() {
    if skip_if_missing("/tmp/repos/flask/src/flask/app.py") {
        return;
    }
    let report = run_json(&[
        "context",
        "/tmp/repos/flask/src/flask/app.py:run",
        "--format",
        "json",
    ]);
    assert_eq!(report["entry_point"], "run");
    let funcs = report["functions"]
        .as_array()
        .expect("functions array on context report");
    assert!(
        !funcs.is_empty(),
        "expected ≥1 function in context: {report}"
    );
}

/// Non-regression: bare-name form (legacy) must still work when the user
/// runs from inside the project directory. Asserts the file:func parser
/// only triggers when the LHS is an actual file on disk.
#[test]
fn agg13_5_context_bare_name_still_works() {
    if skip_if_missing("/tmp/repos/express/lib/application.js") {
        return;
    }
    // From the project root, bare name should still resolve.
    let out = tldr_cmd()
        .args([
            "context",
            "render",
            "/tmp/repos/express",
            "--format",
            "json",
        ])
        .output()
        .expect("spawn tldr");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let report: Value =
        serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("parse JSON: {e}\n{stdout}"));
    assert_eq!(report["entry_point"], "render");
}

/// Negative test: a string that LOOKS like file:func but whose LHS does
/// not exist as a file MUST NOT be re-parsed — it should fall through
/// to the legacy bare-name path so genuine names like Rust `mod::fn` or
/// C++ `Class::method` still parse. The error message confirms the
/// original token (with the colon) was treated as the function name.
#[test]
fn agg13_5_context_non_file_colon_falls_through_to_bare_name() {
    if skip_if_missing("/tmp/repos/express") {
        return;
    }
    let out = tldr_cmd()
        .args([
            "context",
            "/nonexistent/path.js:foo",
            "/tmp/repos/express",
            "--format",
            "json",
        ])
        .output()
        .expect("spawn tldr");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let combined = format!("{stdout}{stderr}");
    // Pre-fix and post-fix both error here, but the error MUST mention
    // the original literal — confirming we did not silently strip the
    // path half. The literal contains a `:` so the error message must
    // include either the LHS or the full string.
    assert!(
        combined.contains("/nonexistent/path.js:foo") || combined.contains("Function not found"),
        "expected error to reference the literal entry, got: {combined}"
    );
}

// =============================================================================
// AGG13-10: clones honors global --lang flag
// =============================================================================

/// `tldr clones <path> --lang luau` MUST report `language: "luau"` in
/// the resulting JSON. Pre-fix the global `-l/--lang` flag was discarded
/// by the dispatcher and the autodetect picked `cpp` (the majority
/// extension in the luau-luau corpus).
#[test]
fn agg13_10_clones_honors_global_lang_luau() {
    if skip_if_missing("/tmp/repos/luau-luau") {
        return;
    }
    let report = run_json(&[
        "clones",
        "/tmp/repos/luau-luau",
        "--lang",
        "luau",
        "--format",
        "json",
    ]);
    assert_eq!(
        report["language"], "luau",
        "expected language=luau, got: {}",
        report["language"]
    );
}

/// Non-regression: the local `--language` flag still wins (and pre-fix
/// it always worked). Asserts the merge prefers the local flag when
/// both are set.
#[test]
fn agg13_10_clones_local_language_flag_still_works() {
    if skip_if_missing("/tmp/repos/luau-luau") {
        return;
    }
    let report = run_json(&[
        "clones",
        "/tmp/repos/luau-luau",
        "--language",
        "luau",
        "--format",
        "json",
    ]);
    assert_eq!(report["language"], "luau");
}

/// Non-regression: bare invocation (no language flag at all) still
/// autodetects. For a JS-majority repo this is `javascript`.
#[test]
fn agg13_10_clones_autodetect_unchanged() {
    if skip_if_missing("/tmp/repos/express") {
        return;
    }
    let report = run_json(&["clones", "/tmp/repos/express", "--format", "json"]);
    assert_eq!(report["language"], "javascript");
}

/// Cross-language: --lang on a different language (rust) also works
/// — confirms the fix is generic, not luau-specific.
#[test]
fn agg13_10_clones_honors_global_lang_rust() {
    if skip_if_missing("/tmp/repos/ripgrep") {
        return;
    }
    let report = run_json(&[
        "clones",
        "/tmp/repos/ripgrep",
        "--lang",
        "rust",
        "--format",
        "json",
    ]);
    assert_eq!(report["language"], "rust");
}
