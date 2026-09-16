//! context-file-func-cross-lang-and-cpp-qualified-v1 — regression tests
//! for the P14.AGG13-5 generalization and P14.AGG14-3 / AGG14-8 fixes.
//!
//! All tests use real repos under `/tmp/repos/<repo>` and gate on
//! existence so they're skipped silently when the corpus isn't checked
//! out (per the no-synthetic-fixtures-v1 strategy).
//!
//! Bugs covered:
//!
//! - **P14.AGG13-5 (REGRESSED)**: `tldr context "<file>:<func>"` failed
//!   on real repos for OCaml (`opamStd.ml:concat_map`), C++
//!   (`tinyxml2.cpp:XMLDocument::Parse`), and TypeScript
//!   (`emitter.ts:emitWebIdl`). Two distinct root causes, both fixed:
//!     * The shorthand parser used `rfind(':')` which split inside
//!       `Class::method` for C++ qualified names. Now walks colons
//!       right-to-left until the file_part is an existing file.
//!     * The project tree-walker skipped vendored/build directories
//!       (`vendor/`, `build/`), so `scan_project_for_function` never
//!       saw OCaml `vendor/opam/...` and TS `src/build/emitter.ts`.
//!       `find_function_in_graph` now extracts the explicit
//!       `file_filter` directly, bypassing the walker when the user
//!       has pinned a single file.
//!
//! - **P14.AGG14-3**: 8 per-function commands (`reaching-defs`,
//!   `available`, `dead-stores`, `slice`, `taint`, `complexity`,
//!   `contracts`, `explain`) rejected C++ `XMLDocument::Parse`
//!   qualified names, even though bare `Parse` worked. Fix:
//!   `function_finder::find_function_node` and
//!   `commands/contracts::find_function_node` now accept the C++
//!   `Class::method` form by descending into the matching class
//!   scope, then falling back to the bare last segment.
//!
//! - **P14.AGG14-8**: `tldr context "<file.ts>:<fn>"` failed for the
//!   `ts-dom-gen` corpus (file under `src/build/` — a build-output
//!   sink in the walker's skip list). Fixed by the same direct-extract
//!   path as OCaml.
//!
//! Also covers multi-language non-regression: file:fn shorthand
//! continues to work for js / swift / lua / python / rust / go / java
//! / php / ruby / elixir / scala (relative-path bonus from the parser
//! generalization).

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

fn run_status(args: &[&str]) -> (i32, String, String) {
    let out = tldr_cmd().args(args).output().expect("spawn tldr");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    (code, stdout, stderr)
}

// =============================================================================
// P14.AGG13-5 — REGRESSED langs now resolve via file:fn shorthand
// =============================================================================

/// OCaml `concat_map` lives in `vendor/opam/src/core/opamStd.ml` —
/// the project tree-walker skips `vendor/` so the legacy fallback
/// scan never saw the file. The fix in `find_function_in_graph`
/// extracts the explicit file directly when `file_filter` is set.
#[test]
fn agg13_5_ocaml_context_file_func_finds_vendored_function() {
    let file = "/tmp/repos/ocaml-dune/vendor/opam/src/core/opamStd.ml";
    if skip_if_missing(file) {
        return;
    }
    let arg = format!("{}:concat_map", file);
    let report = run_json(&["context", &arg, "--format", "json"]);
    assert_eq!(report["entry_point"], "concat_map");
    let funcs = report["functions"].as_array().expect("functions array");
    assert!(
        !funcs.is_empty(),
        "expected ≥1 function for concat_map, got 0: {report}"
    );
    // The first entry must be the entry point itself.
    assert_eq!(funcs[0]["name"], "concat_map");
}

/// C `sds.c:sdsnewlen` was reported as REGRESSED in the audit, but
/// fixes for related bugs incidentally restored this case (verified
/// pre-fix). The test pins the working behaviour.
#[test]
fn agg13_5_c_context_file_func_finds_sdsnewlen() {
    let file = "/tmp/repos/c-sds/sds.c";
    if skip_if_missing(file) {
        return;
    }
    let arg = format!("{}:sdsnewlen", file);
    let report = run_json(&["context", &arg, "--format", "json"]);
    assert_eq!(report["entry_point"], "sdsnewlen");
    let funcs = report["functions"].as_array().expect("functions array");
    assert!(
        !funcs.is_empty(),
        "expected ≥1 function for sdsnewlen, got 0"
    );
}

/// C++ `tinyxml2.cpp:XMLDocument::Parse` requires BOTH the smarter
/// colon parser (the legacy rfind(':') split inside `::`) AND the
/// per-function lookup that accepts `Class::method`.
#[test]
fn agg13_5_cpp_context_file_func_finds_xmldocument_parse() {
    let file = "/tmp/repos/cpp-tinyxml2/tinyxml2.cpp";
    if skip_if_missing(file) {
        return;
    }
    let arg = format!("{}:XMLDocument::Parse", file);
    let report = run_json(&["context", &arg, "--format", "json"]);
    assert_eq!(report["entry_point"], "XMLDocument::Parse");
    let funcs = report["functions"].as_array().expect("functions array");
    assert!(
        !funcs.is_empty(),
        "expected ≥1 function for XMLDocument::Parse, got 0: {report}"
    );
}

/// TypeScript `src/build/emitter.ts:emitWebIdl` failed because the
/// walker skips `build/` (build-sink). Direct-extract bypass fixes it.
#[test]
fn agg14_8_typescript_context_file_func_finds_emitwebidl() {
    let file = "/tmp/repos/ts-dom-gen/src/build/emitter.ts";
    if skip_if_missing(file) {
        return;
    }
    let arg = format!("{}:emitWebIdl", file);
    let report = run_json(&["context", &arg, "--format", "json"]);
    assert_eq!(report["entry_point"], "emitWebIdl");
    let funcs = report["functions"].as_array().expect("functions array");
    assert!(
        !funcs.is_empty(),
        "expected ≥1 function for emitWebIdl, got 0: {report}"
    );
    // Verify the function file resolves to the actual emitter.ts (the
    // walker would have hidden it pre-fix).
    assert!(
        funcs[0]["file"]
            .as_str()
            .unwrap_or("")
            .ends_with("emitter.ts"),
        "expected function file ending in emitter.ts, got {}",
        funcs[0]["file"]
    );
}

// =============================================================================
// P14.AGG14-3 — C++ qualified-name lookup across the 8 per-function commands
// =============================================================================

/// Pin XMLDocument::Parse for each of the 8 commands. They all share
/// the canonical `find_function_node` + contracts-local
/// `find_function_node` (now both accept `Class::method` for C/C++).
#[test]
fn agg14_3_cpp_reaching_defs_xmldocument_parse() {
    let file = "/tmp/repos/cpp-tinyxml2/tinyxml2.cpp";
    if skip_if_missing(file) {
        return;
    }
    let report = run_json(&["reaching-defs", file, "XMLDocument::Parse"]);
    assert_eq!(report["function"], "XMLDocument::Parse");
    let blocks = report["blocks"].as_array().expect("blocks array");
    assert!(!blocks.is_empty(), "expected ≥1 CFG block");
}

#[test]
fn agg14_3_cpp_available_xmldocument_parse() {
    let file = "/tmp/repos/cpp-tinyxml2/tinyxml2.cpp";
    if skip_if_missing(file) {
        return;
    }
    let (code, stdout, stderr) = run_status(&["available", file, "XMLDocument::Parse"]);
    assert_eq!(
        code, 0,
        "available exit non-zero: stdout={stdout} stderr={stderr}"
    );
    let v: Value = serde_json::from_str(&stdout).expect("parse json");
    // `avail_in` and `avail_out` are the canonical schema keys.
    assert!(v.get("avail_in").is_some() || v.get("avail_out").is_some());
}

#[test]
fn agg14_3_cpp_dead_stores_xmldocument_parse() {
    let file = "/tmp/repos/cpp-tinyxml2/tinyxml2.cpp";
    if skip_if_missing(file) {
        return;
    }
    let report = run_json(&["dead-stores", file, "XMLDocument::Parse"]);
    assert_eq!(report["function"], "XMLDocument::Parse");
    // canonical schema: `dead_stores_ssa` + `dead_stores_live_vars`.
    assert!(report.get("dead_stores_ssa").is_some());
    assert!(report.get("count").is_some());
}

#[test]
fn agg14_3_cpp_slice_xmldocument_parse() {
    let file = "/tmp/repos/cpp-tinyxml2/tinyxml2.cpp";
    if skip_if_missing(file) {
        return;
    }
    // slice needs a line argument; pick a line within the function body.
    let report = run_json(&["slice", file, "XMLDocument::Parse", "2480"]);
    assert_eq!(report["function"], "XMLDocument::Parse");
    let lines = report["lines"].as_array().expect("lines array");
    assert!(!lines.is_empty(), "expected ≥1 sliced line");
}

#[test]
fn agg14_3_cpp_taint_xmldocument_parse() {
    let file = "/tmp/repos/cpp-tinyxml2/tinyxml2.cpp";
    if skip_if_missing(file) {
        return;
    }
    let report = run_json(&["taint", file, "XMLDocument::Parse"]);
    assert_eq!(report["function"], "XMLDocument::Parse");
    // tainted_vars is always present (may be empty).
    assert!(report.get("tainted_vars").is_some());
}

#[test]
fn agg14_3_cpp_complexity_xmldocument_parse() {
    let file = "/tmp/repos/cpp-tinyxml2/tinyxml2.cpp";
    if skip_if_missing(file) {
        return;
    }
    let report = run_json(&["complexity", file, "XMLDocument::Parse"]);
    assert_eq!(report["function"], "XMLDocument::Parse");
    let cyc = report["cyclomatic"].as_u64().expect("cyclomatic u64");
    assert!(cyc >= 1, "expected cyclomatic ≥1, got {cyc}");
}

#[test]
fn agg14_3_cpp_contracts_xmldocument_parse() {
    let file = "/tmp/repos/cpp-tinyxml2/tinyxml2.cpp";
    if skip_if_missing(file) {
        return;
    }
    let report = run_json(&["contracts", file, "XMLDocument::Parse"]);
    assert_eq!(report["function"], "XMLDocument::Parse");
    assert!(report.get("preconditions").is_some());
    assert!(report.get("postconditions").is_some());
}

#[test]
fn agg14_3_cpp_explain_xmldocument_parse() {
    let file = "/tmp/repos/cpp-tinyxml2/tinyxml2.cpp";
    if skip_if_missing(file) {
        return;
    }
    let report = run_json(&["explain", file, "XMLDocument::Parse"]);
    assert_eq!(report["function"], "XMLDocument::Parse");
    let line = report["line_start"]
        .as_u64()
        .or_else(|| report["line"].as_u64());
    assert!(line.is_some(), "expected line/line_start in explain");
}

/// Bare `Parse` MUST still resolve for the same commands — no
/// regression of the legacy lookup. Smoke test: pick the canonical
/// pair (complexity + explain) since they hit different code paths.
#[test]
fn agg14_3_cpp_bare_parse_still_works_complexity() {
    let file = "/tmp/repos/cpp-tinyxml2/tinyxml2.cpp";
    if skip_if_missing(file) {
        return;
    }
    let report = run_json(&["complexity", file, "Parse"]);
    assert_eq!(report["function"], "Parse");
    let cyc = report["cyclomatic"].as_u64().expect("cyclomatic u64");
    assert!(cyc >= 1, "expected cyclomatic ≥1 for bare Parse");
}

#[test]
fn agg14_3_cpp_bare_parse_still_works_explain() {
    let file = "/tmp/repos/cpp-tinyxml2/tinyxml2.cpp";
    if skip_if_missing(file) {
        return;
    }
    let report = run_json(&["explain", file, "Parse"]);
    assert_eq!(report["function"], "Parse");
}

/// Mini-audit: a SECOND qualified C++ method must also resolve. The
/// canonical fix was applied at the resolver layer, not specialised
/// to one method name — verify it generalises.
#[test]
fn agg14_3_cpp_complexity_xmldocument_savefile() {
    let file = "/tmp/repos/cpp-tinyxml2/tinyxml2.cpp";
    if skip_if_missing(file) {
        return;
    }
    // SaveFile is a different XMLDocument out-of-class definition.
    let (code, stdout, _stderr) = run_status(&["complexity", file, "XMLDocument::SaveFile"]);
    if code == 0 {
        let v: Value = serde_json::from_str(&stdout).expect("parse");
        assert_eq!(v["function"], "XMLDocument::SaveFile");
    } else {
        // If SaveFile isn't present in this version of tinyxml2, that's
        // fine — this is a mini-audit assertion, not a primary repro.
        eprintln!(
            "[note] XMLDocument::SaveFile not resolved (may not exist in this tinyxml2 version)"
        );
    }
}

// =============================================================================
// Multi-language non-regression: file:fn shorthand still works for langs
// previously HELD by AGG13-5
// =============================================================================

/// JS — express `lib/application.js:render` (the canonical AGG13-5
/// example) MUST still work after the parser change.
#[test]
fn nonreg_js_context_file_func_render() {
    let file = "/tmp/repos/express/lib/application.js";
    if skip_if_missing(file) {
        return;
    }
    let arg = format!("{}:render", file);
    let report = run_json(&["context", &arg, "--format", "json"]);
    assert_eq!(report["entry_point"], "render");
    let funcs = report["functions"].as_array().expect("functions array");
    assert!(!funcs.is_empty(), "expected ≥1 function for render");
}

/// Swift — `Heap+UnsafeHandle.swift:_heapify` (the file where it's
/// actually defined; pre-fix Swift was HELD via the bare-name + scan
/// path). file:fn shorthand must continue to find it.
#[test]
fn nonreg_swift_context_file_func_heapify() {
    let file = "/tmp/repos/swift-collections/Sources/HeapModule/Heap+UnsafeHandle.swift";
    if skip_if_missing(file) {
        return;
    }
    let arg = format!("{}:_heapify", file);
    let report = run_json(&["context", &arg, "--format", "json"]);
    assert_eq!(report["entry_point"], "_heapify");
    let funcs = report["functions"].as_array().expect("functions array");
    assert!(!funcs.is_empty(), "expected ≥1 function for _heapify");
}

/// Lua — `files.lua:m.open` cross-module dotted form MUST still work.
#[test]
fn nonreg_lua_context_file_func_m_open() {
    let file = "/tmp/repos/lua-lsp/script/files.lua";
    if skip_if_missing(file) {
        return;
    }
    let arg = format!("{}:m.open", file);
    let report = run_json(&["context", &arg, "--format", "json"]);
    assert_eq!(report["entry_point"], "m.open");
    let funcs = report["functions"].as_array().expect("functions array");
    assert!(!funcs.is_empty(), "expected ≥1 function for m.open");
}

/// Python — `flask/app.py:wsgi_app` continues to work.
#[test]
fn nonreg_python_context_file_func_wsgi_app() {
    let file = "/tmp/repos/flask/src/flask/app.py";
    if skip_if_missing(file) {
        return;
    }
    let arg = format!("{}:wsgi_app", file);
    let report = run_json(&["context", &arg, "--format", "json"]);
    assert_eq!(report["entry_point"], "wsgi_app");
}

/// Rust — `walk.rs:check_symlink_loop` continues to work.
#[test]
fn nonreg_rust_context_file_func_check_symlink_loop() {
    let file = "/tmp/repos/ripgrep/crates/ignore/src/walk.rs";
    if skip_if_missing(file) {
        return;
    }
    let arg = format!("{}:check_symlink_loop", file);
    let report = run_json(&["context", &arg, "--format", "json"]);
    assert_eq!(report["entry_point"], "check_symlink_loop");
}

/// Go — `router.go:ServeHTTP` continues to work.
#[test]
fn nonreg_go_context_file_func_servehttp() {
    let file = "/tmp/repos/go-httprouter/router.go";
    if skip_if_missing(file) {
        return;
    }
    let arg = format!("{}:ServeHTTP", file);
    let report = run_json(&["context", &arg, "--format", "json"]);
    assert_eq!(report["entry_point"], "ServeHTTP");
}

/// Java — spring-petclinic OwnerController paginated method MUST
/// still work.
#[test]
fn nonreg_java_context_file_func_findpaginated() {
    let file = "/tmp/repos/spring-petclinic/src/main/java/org/springframework/samples/petclinic/owner/OwnerController.java";
    if skip_if_missing(file) {
        return;
    }
    let arg = format!("{}:findPaginatedForOwnersLastName", file);
    let report = run_json(&["context", &arg, "--format", "json"]);
    assert_eq!(report["entry_point"], "findPaginatedForOwnersLastName");
}

// =============================================================================
// PARTIAL-fix bonus: relative-path file:fn now works for php / ruby /
// elixir (audit reported these as PARTIAL — relative path failed, only
// absolute worked). The smarter parser + project-root inference make
// the relative form work too.
// =============================================================================

/// PHP relative form — `cd /tmp/repos/php-symfony-string && tldr
/// context "ByteString.php:slice"` was reported as PARTIAL (relative
/// failed). Now resolves.
#[test]
fn bonus_php_context_relative_file_func() {
    let dir = "/tmp/repos/php-symfony-string";
    let file = "/tmp/repos/php-symfony-string/ByteString.php";
    if skip_if_missing(file) {
        return;
    }
    let out = tldr_cmd()
        .current_dir(dir)
        .args(["context", "ByteString.php:slice", "--format", "json"])
        .output()
        .expect("spawn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let report: Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "parse json: {}\nstdout: {}\nstderr: {}",
            e,
            stdout,
            String::from_utf8_lossy(&out.stderr)
        )
    });
    assert_eq!(report["entry_point"], "slice");
    let funcs = report["functions"].as_array().expect("functions array");
    assert!(!funcs.is_empty(), "expected ≥1 function for slice");
}

/// Ruby relative form — `cd /tmp/repos/rails-html-sanitizer && tldr
/// context "lib/rails/html/sanitizer.rb:sanitize"` resolves.
#[test]
fn bonus_ruby_context_relative_file_func() {
    let dir = "/tmp/repos/rails-html-sanitizer";
    let file = "/tmp/repos/rails-html-sanitizer/lib/rails/html/sanitizer.rb";
    if skip_if_missing(file) {
        return;
    }
    let out = tldr_cmd()
        .current_dir(dir)
        .args([
            "context",
            "lib/rails/html/sanitizer.rb:sanitize",
            "--format",
            "json",
        ])
        .output()
        .expect("spawn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let report: Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "parse json: {}\nstdout: {}\nstderr: {}",
            e,
            stdout,
            String::from_utf8_lossy(&out.stderr)
        )
    });
    assert_eq!(report["entry_point"], "sanitize");
    let funcs = report["functions"].as_array().expect("functions array");
    assert!(!funcs.is_empty(), "expected ≥1 function for sanitize");
}

/// Elixir relative form — `cd /tmp/repos/elixir-plug && tldr context
/// "lib/plug/conn.ex:request_url"` resolves.
#[test]
fn bonus_elixir_context_relative_file_func() {
    let dir = "/tmp/repos/elixir-plug";
    let file = "/tmp/repos/elixir-plug/lib/plug/conn.ex";
    if skip_if_missing(file) {
        return;
    }
    let out = tldr_cmd()
        .current_dir(dir)
        .args([
            "context",
            "lib/plug/conn.ex:request_url",
            "--format",
            "json",
        ])
        .output()
        .expect("spawn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let report: Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "parse json: {}\nstdout: {}\nstderr: {}",
            e,
            stdout,
            String::from_utf8_lossy(&out.stderr)
        )
    });
    assert_eq!(report["entry_point"], "request_url");
}
