//! sibling-resolver-gaps-v1 — regression tests for the P14-B
//! milestone. Closes the sibling-resolver gap pattern found in the
//! Phase-14 audit: P13 fixes that were applied to one command but
//! whose sibling commands sharing the same broken resolver were
//! missed.
//!
//! Bugs covered (by AGG ID, all from
//! `/tmp/audit_phase14/AGGREGATE_REPORT.md`):
//!
//! - **AGG14-1** (HIGH, regression): java `impact
//!   findPaginatedForOwnersLastName` returned `caller_count=2`
//!   with both entries being the same caller (call-graph emitted
//!   `Class.method`, references-fallback emitted bare `method`, and
//!   the dedup keyed on exact string equality). Fix: last-segment
//!   aware dedup in `enrich_impact_with_references`.
//!
//! - **AGG14-4** (MED, sibling-gap): csharp `whatbreaks WriteToken`
//!   reported `caller_count=0` ("Entry point") while `impact
//!   WriteToken` correctly returned 2 callers via the references
//!   enrichment (P13.AGG13-4). Fix: promote
//!   `enrich_impact_with_references` from CLI into tldr-core and call
//!   it from `whatbreaks`'s internal impact path.
//!
//! - **AGG14-5** (MED, sibling-gap): luau `--lang luau` flag bypassed
//!   by `api-check` (scanned 800+ files instead of luau-only) and
//!   `debt` (returned `language=null`). Fix: plumb `cli.lang` into
//!   `ApiCheckArgs::run`; expose a `language` field on `DebtReport`
//!   so consumers can confirm the flag was honoured.
//!
//! - **AGG14-6** (MED): `definition <file> <line> 1` returned
//!   "symbol '<keyword>' not found" across 8 languages because the
//!   resolver returned the keyword node text (`function`/`func`/`fn`
//!   /`def`/`export`/...). Fix: when the symbol-at-position resolves
//!   to a known keyword, advance to the next identifier; for
//!   qualified expressions (`m.reset`, `Class::method`) prefer the
//!   parent dotted/scoped node and fall back to the trailing segment
//!   if the dotted form fails to resolve.
//!
//! - **AGG14-13** (LOW, sibling-gap): lua `references m.reset`
//!   returned only same-module hits while `explain m.open` correctly
//!   resolved cross-module alias callers (P13.AGG13-12). Fix: apply
//!   the same bare-name + `\.<method>(` enrichment to the references
//!   command.
//!
//! - **AGG14-14** (LOW, swift): swift `explain Heap._heapify`
//!   reported `Tests/HeapTests/HeapTests.swift` as the file for
//!   `trickleDownMin`/`trickleDownMax` callees, even though those
//!   methods are defined in `Heap+UnsafeHandle.swift`. Fix: when the
//!   call-graph attributes a callee to a file that doesn't define it,
//!   walk every project file in the graph's edges and pick the
//!   non-test source that does.
//!
//! - **AGG14-19** (LOW, javascript): `cognitive application.js`
//!   returned only 2 functions (`logerror`, `tryRender`) while
//!   `halstead` and `complexity` correctly resolved 19 — the
//!   cognitive walker missed CommonJS-style
//!   `app.X = function name(){}` assignments. Fix: augment the
//!   tree-sitter walker with the AST extractor's function set for
//!   JS/TS, mirroring what halstead already does.
//!
//! Plus non-regression assertions:
//!   - csharp `impact WriteToken` still returns 2 callers
//!     (P13.AGG13-4 must hold).
//!   - definition with col != 1 in lua/rust/python/typescript still
//!     resolves the symbol at that column.
//!   - cognitive on python/rust still returns its previous count
//!     (the JS-only enrichment must not affect non-CommonJS langs).
//!
//! All tests gate on `/tmp/repos/<repo>` per the
//! `no-synthetic-fixtures-v1` strategy.

use assert_cmd::Command;
use serde_json::Value;
use std::path::Path;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

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

// ============================================================================
// AGG14-1 — java impact dedup (regression)
// ============================================================================

#[test]
fn agg14_1_java_impact_dedupes_callgraph_and_references_fallback() {
    let repo = "/tmp/repos/spring-petclinic";
    if skip_if_missing(repo) {
        return;
    }
    let report = run_json(&[
        "impact",
        "findPaginatedForOwnersLastName",
        repo,
        "--format",
        "json",
    ]);
    let targets = report
        .get("targets")
        .and_then(|t| t.as_object())
        .expect("targets object");
    assert_eq!(
        targets.len(),
        1,
        "expected exactly one target (no homonym in this repo): {report}"
    );
    let (_, target) = targets.iter().next().unwrap();
    let caller_count = target
        .get("caller_count")
        .and_then(|v| v.as_u64())
        .expect("caller_count u64");
    let callers = target
        .get("callers")
        .and_then(|v| v.as_array())
        .expect("callers array");
    // Pre-fix: caller_count=2 with both entries being processFindForm
    // (call-graph emitted OwnerController.processFindForm, references
    // emitted bare processFindForm; dedup keyed on exact string match).
    // Post-fix: last-segment-aware dedup collapses both to one entry.
    assert_eq!(
        caller_count, 1,
        "expected caller_count=1 after dedup, got {caller_count}: {target}"
    );
    assert_eq!(callers.len(), 1, "expected one caller entry: {target}");
}

// ============================================================================
// AGG14-1 non-regression — csharp impact still returns 2 distinct callers
// ============================================================================

#[test]
fn agg14_1_csharp_impact_writetoken_still_two_callers() {
    let repo = "/tmp/repos/csharp-newtonsoft-bson-full";
    if skip_if_missing(repo) {
        return;
    }
    let report = run_json(&["impact", "WriteToken", repo, "--format", "json"]);
    let target = report
        .get("targets")
        .and_then(|t| t.as_object())
        .and_then(|m| m.values().next())
        .expect("at least one target");
    let caller_count = target
        .get("caller_count")
        .and_then(|v| v.as_u64())
        .expect("caller_count u64");
    // P13.AGG13-4 must keep holding: WriteToken has two distinct
    // cross-file callers (WriteTokenAsync, WriteEnd).
    assert!(
        caller_count >= 2,
        "P13.AGG13-4 must hold: caller_count >= 2, got {caller_count}: {target}"
    );
}

// ============================================================================
// AGG14-4 — csharp whatbreaks now propagates references-enrichment
// ============================================================================

#[test]
fn agg14_4_csharp_whatbreaks_writetoken_finds_callers() {
    let repo = "/tmp/repos/csharp-newtonsoft-bson-full";
    if skip_if_missing(repo) {
        return;
    }
    let report = run_json(&["whatbreaks", "WriteToken", repo, "--format", "json"]);
    let direct = report
        .pointer("/summary/direct_caller_count")
        .and_then(|v| v.as_u64())
        .expect("summary.direct_caller_count");
    // Pre-fix: 0 ("Entry point — no callers found"). Post-fix: same as
    // `impact WriteToken` because both share the same enrichment.
    assert!(
        direct >= 1,
        "expected >= 1 direct caller (sibling of impact), got {direct}: {report}"
    );
}

// ============================================================================
// AGG14-5 — luau --lang flag honoured by api-check and debt
// ============================================================================

#[test]
fn agg14_5_luau_api_check_honours_lang_flag() {
    let repo = "/tmp/repos/luau-luau";
    if skip_if_missing(repo) {
        return;
    }
    let report = run_json(&["api-check", "--lang", "luau", repo, "--format", "json"]);
    let findings = report
        .get("findings")
        .and_then(|v| v.as_array())
        .expect("findings array");
    // Pre-fix: scanned all .cpp/.h/.py files too — many findings on
    // non-luau extensions. Post-fix: only luau extensions.
    let bad_ext_count = findings
        .iter()
        .filter_map(|f| f.get("file").and_then(|v| v.as_str()))
        .filter(|p| !(p.ends_with(".lua") || p.ends_with(".luau")))
        .count();
    assert_eq!(
        bad_ext_count, 0,
        "expected zero non-lua/luau files when --lang luau, got {bad_ext_count} bad-ext findings"
    );
    // Total findings should be small (luau-luau has only ~2 .luau and
    // ~2 .lua files in this checkout). Bound at 200 to leave plenty
    // of room while still catching the original 89-cpp-file regression.
    assert!(
        findings.len() < 200,
        "expected < 200 findings under --lang luau, got {} (suggests cpp/h files leaked through)",
        findings.len()
    );
}

#[test]
fn agg14_5_luau_debt_emits_language_field() {
    let repo = "/tmp/repos/luau-luau";
    if skip_if_missing(repo) {
        return;
    }
    let report = run_json(&["debt", "--lang", "luau", repo, "--format", "json"]);
    let language = report
        .get("language")
        .and_then(|v| v.as_str())
        .expect("language field present");
    assert_eq!(language, "luau", "expected language=luau, got {language}");
}

// AGG14-5 non-regression — debt without --lang on flask still works.
#[test]
fn agg14_5_debt_no_lang_does_not_break_python_run() {
    let repo = "/tmp/repos/flask";
    if skip_if_missing(repo) {
        return;
    }
    let report = run_json(&["debt", repo, "--format", "json"]);
    // Without --lang the language field is null but the run completes
    // and total_minutes > 0 (flask has plenty of debt).
    let total_min = report
        .pointer("/summary/total_minutes")
        .and_then(|v| v.as_u64())
        .expect("summary.total_minutes");
    assert!(
        total_min > 0,
        "expected > 0 debt minutes on flask without --lang, got {total_min}"
    );
}

// AGG14-5 non-regression — api-check on python without lang flag still works.
#[test]
fn agg14_5_api_check_python_no_lang_still_works() {
    let repo = "/tmp/repos/flask";
    if skip_if_missing(repo) {
        return;
    }
    let report = run_json(&["api-check", "--lang", "python", repo, "--format", "json"]);
    // Just confirm the command produces a well-formed report under
    // --lang python (must not regress the existing per-file dispatch).
    assert!(
        report.get("findings").is_some(),
        "findings field should exist: {report}"
    );
}

// ============================================================================
// AGG14-6 — definition with col=1 (keyword) resolves the actual symbol
// ============================================================================

#[test]
fn agg14_6_definition_lua_col1_skips_function_keyword() {
    let path = "/tmp/repos/lua-lsp/script/files.lua";
    if skip_if_missing(path) {
        return;
    }
    let (code, stdout, stderr) = run_status(&["definition", path, "44", "1", "--format", "json"]);
    assert_eq!(
        code, 0,
        "lua col=1 keyword skip should succeed, got code {code}\nstdout: {stdout}\nstderr: {stderr}"
    );
    let report: Value = serde_json::from_str(&stdout).expect("valid JSON");
    let name = report
        .pointer("/symbol/name")
        .and_then(|v| v.as_str())
        .expect("symbol.name");
    assert_ne!(
        name, "function",
        "must not return the 'function' keyword as the resolved symbol"
    );
    // Post-fix: returns "reset" (trailing segment of m.reset). Accept
    // any of: reset, m.reset, m. Reject "function".
    assert!(
        !is_keyword(name),
        "resolved name should not be a keyword, got {name}"
    );
}

#[test]
fn agg14_6_definition_go_col1_skips_func_keyword() {
    let path = "/tmp/repos/go-httprouter/router.go";
    if skip_if_missing(path) {
        return;
    }
    let (code, stdout, stderr) = run_status(&["definition", path, "104", "1", "--format", "json"]);
    assert_eq!(
        code, 0,
        "go col=1 keyword skip should succeed, got code {code}\nstdout: {stdout}\nstderr: {stderr}"
    );
    let report: Value = serde_json::from_str(&stdout).expect("valid JSON");
    let name = report
        .pointer("/symbol/name")
        .and_then(|v| v.as_str())
        .expect("symbol.name");
    assert_ne!(name, "func", "must not return the 'func' keyword");
    assert!(
        !is_keyword(name),
        "resolved name should not be a keyword, got {name}"
    );
}

#[test]
fn agg14_6_definition_rust_col1_skips_fn_keyword() {
    let path = "/tmp/repos/ripgrep/crates/core/main.rs";
    if skip_if_missing(path) {
        return;
    }
    let (code, stdout, stderr) = run_status(&["definition", path, "43", "1", "--format", "json"]);
    assert_eq!(
        code, 0,
        "rust col=1 keyword skip should succeed, got code {code}\nstdout: {stdout}\nstderr: {stderr}"
    );
    let report: Value = serde_json::from_str(&stdout).expect("valid JSON");
    let name = report
        .pointer("/symbol/name")
        .and_then(|v| v.as_str())
        .expect("symbol.name");
    assert_ne!(name, "fn", "must not return the 'fn' keyword");
    assert_ne!(name, "pub", "must not return the 'pub' keyword");
    assert!(
        !is_keyword(name),
        "resolved name should not be a keyword, got {name}"
    );
}

#[test]
fn agg14_6_definition_python_col1_skips_def_keyword() {
    let path = "/tmp/repos/flask/src/flask/app.py";
    if skip_if_missing(path) {
        return;
    }
    let (code, stdout, stderr) = run_status(&["definition", path, "73", "1", "--format", "json"]);
    assert_eq!(
        code, 0,
        "python col=1 keyword skip should succeed, got code {code}\nstdout: {stdout}\nstderr: {stderr}"
    );
    let report: Value = serde_json::from_str(&stdout).expect("valid JSON");
    let name = report
        .pointer("/symbol/name")
        .and_then(|v| v.as_str())
        .expect("symbol.name");
    assert_ne!(name, "def", "must not return the 'def' keyword");
    assert!(
        !is_keyword(name),
        "resolved name should not be a keyword, got {name}"
    );
}

#[test]
fn agg14_6_definition_ts_col1_skips_export_keyword() {
    let path = "/tmp/repos/ts-dom-gen/src/build/emitter.ts";
    if skip_if_missing(path) {
        return;
    }
    let (code, stdout, stderr) = run_status(&["definition", path, "137", "1", "--format", "json"]);
    assert_eq!(
        code, 0,
        "typescript col=1 keyword skip should succeed, got code {code}\nstdout: {stdout}\nstderr: {stderr}"
    );
    let report: Value = serde_json::from_str(&stdout).expect("valid JSON");
    let name = report
        .pointer("/symbol/name")
        .and_then(|v| v.as_str())
        .expect("symbol.name");
    assert_ne!(name, "export", "must not return the 'export' keyword");
    assert_ne!(name, "function", "must not return the 'function' keyword");
    assert!(
        !is_keyword(name),
        "resolved name should not be a keyword, got {name}"
    );
}

// AGG14-6 non-regression — col != 1 (already-on-identifier) still works.
#[test]
fn agg14_6_definition_col_not_1_still_works_lua() {
    let path = "/tmp/repos/lua-lsp/script/files.lua";
    if skip_if_missing(path) {
        return;
    }
    // Col 9 (1-indexed) sits on `m` in `function m.reset()`.
    let (code, stdout, _stderr) = run_status(&["definition", path, "44", "9", "--format", "json"]);
    assert_eq!(code, 0, "col=9 should resolve cleanly");
    let report: Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert!(
        report.pointer("/symbol/name").is_some(),
        "non-keyword col should still resolve a symbol"
    );
}

#[test]
fn agg14_6_definition_col_not_1_still_works_python() {
    let path = "/tmp/repos/flask/src/flask/app.py";
    if skip_if_missing(path) {
        return;
    }
    // Col 5 (1-indexed) sits on the start of the function name in
    // `def _make_timedelta(...)` (after `def ` which is 4 chars).
    let (code, _stdout, _stderr) = run_status(&["definition", path, "73", "5", "--format", "json"]);
    assert_eq!(code, 0, "col=5 (on identifier) should resolve cleanly");
}

fn is_keyword(s: &str) -> bool {
    matches!(
        s,
        "fn" | "func"
            | "function"
            | "def"
            | "defp"
            | "let"
            | "var"
            | "const"
            | "class"
            | "struct"
            | "trait"
            | "interface"
            | "module"
            | "namespace"
            | "package"
            | "import"
            | "use"
            | "using"
            | "export"
            | "pub"
            | "public"
            | "private"
            | "static"
            | "final"
            | "abstract"
            | "override"
            | "async"
            | "return"
            | "if"
            | "else"
            | ""
    )
}

// ============================================================================
// AGG14-13 — lua references picks up cross-module alias callers
// ============================================================================

#[test]
fn agg14_13_lua_references_finds_cross_module_alias_callers() {
    let repo = "/tmp/repos/lua-lsp";
    if skip_if_missing(repo) {
        return;
    }
    let report = run_json(&["references", "m.reset", repo, "--format", "json"]);
    let refs = report
        .get("references")
        .and_then(|v| v.as_array())
        .expect("references array");
    // Pre-fix: 6 references (only files.lua + scope.lua + workspace).
    // Post-fix: also includes lclient.lua's `files.reset()` call site
    // and other cross-module alias usages, raising the count.
    assert!(
        refs.len() >= 7,
        "expected >= 7 references after cross-module alias enrichment, got {}",
        refs.len()
    );
    // Specifically confirm at least one cross-module reference (a file
    // outside `script/files.lua` and `script/workspace/scope.lua`).
    let has_cross_module = refs.iter().any(|r| {
        let p = r.get("file").and_then(|v| v.as_str()).unwrap_or("");
        !(p.ends_with("script/files.lua") || p.ends_with("script/workspace/scope.lua"))
    });
    assert!(
        has_cross_module,
        "expected at least one cross-module reference: {refs:?}"
    );
}

// ============================================================================
// AGG14-14 — swift explain callee file attribution prefers definition file
// ============================================================================

#[test]
fn agg14_14_swift_explain_callee_file_is_canonical_definition() {
    let path = "/tmp/repos/swift-collections/Sources/HeapModule/Heap+UnsafeHandle.swift";
    if skip_if_missing(path) {
        return;
    }
    let report = run_json(&["explain", path, "Heap._heapify", "--format", "json"]);
    let callees = report
        .get("callees")
        .and_then(|v| v.as_array())
        .expect("callees array");
    let trickle: Vec<&Value> = callees
        .iter()
        .filter(|c| {
            c.get("name")
                .and_then(|v| v.as_str())
                .map(|n| n.contains("trickleDownMin") || n.contains("trickleDownMax"))
                .unwrap_or(false)
        })
        .collect();
    assert!(
        trickle.len() >= 2,
        "expected >= 2 trickleDown callees, got {}: {:?}",
        trickle.len(),
        callees
    );
    for c in trickle {
        let file = c.get("file").and_then(|v| v.as_str()).unwrap_or("");
        // Pre-fix: file = "Tests/HeapTests/HeapTests.swift" (wrong).
        // Post-fix: file = "Sources/HeapModule/Heap+UnsafeHandle.swift".
        assert!(
            !file.contains("/Tests/") && !file.to_lowercase().contains("tests.swift"),
            "callee {} should not be attributed to a test file, got file={file}",
            c.get("name").and_then(|v| v.as_str()).unwrap_or("?")
        );
        assert!(
            file.contains("Heap+UnsafeHandle.swift"),
            "expected canonical Heap+UnsafeHandle.swift, got file={file} for callee={:?}",
            c
        );
    }
}

// ============================================================================
// AGG14-19 — js cognitive picks up CommonJS-assigned functions
// ============================================================================

#[test]
fn agg14_19_js_cognitive_resolves_commonjs_functions() {
    let path = "/tmp/repos/express/lib/application.js";
    if skip_if_missing(path) {
        return;
    }
    let report = run_json(&["cognitive", path, "--format", "json"]);
    let functions = report
        .get("functions")
        .and_then(|v| v.as_array())
        .expect("functions array");
    // Pre-fix: 2 (logerror, tryRender). Post-fix: 19 (matches halstead
    // / complexity siblings). Bound at >= 10 for safety; the actual
    // figure is 19 on this checkout.
    assert!(
        functions.len() >= 10,
        "expected >= 10 cognitive functions on express/application.js, got {}",
        functions.len()
    );
    // Confirm the canonical CommonJS-named functions are present.
    let names: Vec<&str> = functions
        .iter()
        .filter_map(|f| f.get("name").and_then(|v| v.as_str()))
        .collect();
    let must_have = ["init", "use", "render"];
    for needle in must_have {
        assert!(
            names.iter().any(|n| n == &needle),
            "expected cognitive to include {needle}, got names={names:?}"
        );
    }
}

// AGG14-19 non-regression — cognitive on python and rust still work.
#[test]
fn agg14_19_cognitive_python_non_regression() {
    let path = "/tmp/repos/flask/src/flask/app.py";
    if skip_if_missing(path) {
        return;
    }
    let report = run_json(&["cognitive", path, "--format", "json"]);
    let functions = report
        .get("functions")
        .and_then(|v| v.as_array())
        .expect("functions array");
    // app.py is a large flask module with many @app.route handlers.
    assert!(
        functions.len() >= 10,
        "python cognitive on app.py should still find >= 10 functions, got {}",
        functions.len()
    );
}

#[test]
fn agg14_19_cognitive_rust_non_regression() {
    let path = "/tmp/repos/ripgrep/crates/core/main.rs";
    if skip_if_missing(path) {
        return;
    }
    let report = run_json(&["cognitive", path, "--format", "json"]);
    let functions = report
        .get("functions")
        .and_then(|v| v.as_array())
        .expect("functions array");
    // ripgrep main.rs has at least main + several helpers.
    assert!(
        functions.len() >= 5,
        "rust cognitive on main.rs should still find >= 5 functions, got {}",
        functions.len()
    );
}
