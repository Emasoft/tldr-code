//! fix-PW2-F2-contracts-nested (v0.5.0 BACKLOG) — regression tests.
//!
//! `tldr contracts <file> <fn>` reported `Error: function '<fn>' not found`
//! whenever `<fn>` was defined inside another function's body. The
//! contracts resolver (`find_function_recursive` in
//! `commands/contracts/contracts.rs`) walks an allowlist of container /
//! wrapper node-kinds to decide where to descend, and that list omitted
//! function *body* scopes plus the JS IIFE/closure wrapper chain, so a
//! nested function was unreachable.
//!
//! Symptom class (every language/variant must resolve post-fix):
//!   * JS    — `debounce` inside the lodash `runInContext` IIFE.
//!   * Lua   — `clean_value` nested in `gen_scopes`.
//!   * Swift — `cancelAllRequests` inside the GLR-mis-parsed
//!             `open class Session: @unchecked Sendable {`, and the
//!             well-formed func-in-func case.
//!
//! Synthetic TempDir fixtures reproduce the JS/Lua/Swift nesting shapes
//! deterministically; the Swift `@unchecked Sendable` GLR mis-parse and
//! the exact audit targets are additionally asserted against the real
//! corpora when present (gated on existence, skipped cleanly otherwise).

use assert_cmd::Command;
use serde_json::Value;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

/// Run `tldr contracts <file> <fn> --format json` and return the parsed
/// report, asserting the command resolved the function (exit 0 + a
/// `function` field). A `not found` failure surfaces here as a panic with
/// the captured stderr.
fn contracts_resolves(file: &Path, func: &str) -> Value {
    let out = tldr_cmd()
        .env("TLDR_NO_DAEMON", "1")
        .args([
            "contracts",
            file.to_str().unwrap(),
            func,
            "--format",
            "json",
        ])
        .output()
        .expect("spawn tldr");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "`tldr contracts {} {}` failed (exit {:?})\nstdout: {}\nstderr: {}",
        file.display(),
        func,
        out.status.code(),
        stdout,
        stderr
    );
    let report: Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "parse JSON for `tldr contracts {} {}`: {}\nstdout: {}\nstderr: {}",
            file.display(),
            func,
            e,
            stdout,
            stderr
        )
    });
    assert_eq!(
        report.get("function").and_then(Value::as_str),
        Some(func),
        "contracts report should name the resolved function `{}` (got {:?})",
        func,
        report.get("function")
    );
    report
}

/// True (and prints a notice) when `path` is absent, so the real-corpus
/// arms skip cleanly per the no-synthetic-fixtures convention.
fn skip_if_missing(path: &Path) -> bool {
    if !path.exists() {
        eprintln!("[skip] {} not present", path.display());
        return true;
    }
    false
}

// =============================================================================
// Synthetic fixtures — deterministic, cover the symptom class for js/lua/swift
// =============================================================================

/// JS: function nested inside an IIFE-wrapped function expression
/// (`var x = (function(){ function debounce(){} }())`). Mirrors lodash's
/// `runInContext` IIFE around `debounce`.
#[test]
fn js_nested_fn_in_iife_resolves() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("iife.js");
    fs::write(
        &file,
        "var runInContext = (function runInContext(context) {\n\
         \x20 function debounce(func, wait, options) {\n\
         \x20   if (typeof func != 'function') {\n\
         \x20     throw new TypeError('Expected a function');\n\
         \x20   }\n\
         \x20   return func;\n\
         \x20 }\n\
         \x20 return debounce;\n\
         }());\n",
    )
    .unwrap();
    contracts_resolves(&file, "debounce");
}

/// Lua: function nested inside another function's body block. Mirrors
/// lua-lsp `clean_value` nested in `gen_scopes`.
#[test]
fn lua_nested_fn_in_fn_resolves() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("nested.lua");
    fs::write(
        &file,
        "local function gen_scopes(len, ast, uri)\n\
         \x20 local function clean_value(value, owning_a)\n\
         \x20   if value == nil then\n\
         \x20     return nil\n\
         \x20   end\n\
         \x20   return value\n\
         \x20 end\n\
         \x20 return clean_value\n\
         end\n",
    )
    .unwrap();
    contracts_resolves(&file, "clean_value");
}

/// Swift: well-formed func-in-func
/// (`function_declaration > function_body > statements > function_declaration`).
#[test]
fn swift_nested_fn_in_fn_resolves() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("nestfn.swift");
    fs::write(
        &file,
        "func outer(x: Int) -> Int {\n\
         \x20   func innerHelper(y: Int) -> Int {\n\
         \x20       precondition(y > 0)\n\
         \x20       return y * 2\n\
         \x20   }\n\
         \x20   return innerHelper(y: x)\n\
         }\n",
    )
    .unwrap();
    contracts_resolves(&file, "innerHelper");
}

// =============================================================================
// Real-corpus arms — the exact audit targets, incl. the Swift GLR mis-parse
// (`open class Session: @unchecked Sendable {`). Gated on corpus presence.
// =============================================================================

const CORPORA: &str = "/Users/cosimo/.tldr-audit/corpora";

#[test]
fn js_lodash_runincontext_debounce_resolves() {
    let file = Path::new(CORPORA).join("js-lodash/lodash.js");
    if skip_if_missing(&file) {
        return;
    }
    contracts_resolves(&file, "debounce");
}

#[test]
fn lua_lsp_gen_scopes_clean_value_resolves() {
    let file = Path::new(CORPORA).join("lua-lsp/lua-lsp/analyze.lua");
    if skip_if_missing(&file) {
        return;
    }
    contracts_resolves(&file, "clean_value");
}

#[test]
fn swift_alamofire_session_cancel_all_requests_resolves() {
    let file = Path::new(CORPORA).join("swift-alamofire/Source/Core/Session.swift");
    if skip_if_missing(&file) {
        return;
    }
    // `open class Session: @unchecked Sendable {` is GLR-mis-parsed into
    // `function_declaration > ERROR > ERROR > function_declaration`; the
    // ERROR-descent arm must reach the buried method.
    contracts_resolves(&file, "cancelAllRequests");
}
