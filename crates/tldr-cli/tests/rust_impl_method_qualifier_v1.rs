//! rust-impl-qualifier-v1: regression coverage for v0.4.2 audit bug C1
//! (VAL-RUST-QUAL).
//!
//! Background
//! ----------
//! Pre-fix `tldr impact <Type>::<method> /tmp/repos/ripgrep`,
//! `tldr whatbreaks <Type>::<method> /tmp/repos/ripgrep`, and
//! `tldr context "<file>:<Type>::<method>"` dropped the `<Type>::`
//! qualifier and resolved to ALL same-named methods across the rust
//! corpus — polluting the result with unrelated definitions that have
//! nothing to do with the requested type.
//!
//! Concrete example: ripgrep defines two distinct `struct Parser` types
//! — one in `crates/globset/src/glob.rs` (the `globset` glob-pattern
//! parser, used via `impl<'a> Parser<'a>::parse`) and one in
//! `crates/core/flags/parse.rs` (the `rg` command-line flag parser,
//! used via `impl<'p> Parser<'p>::parse`). They are unrelated. Pre-fix
//! `tldr impact Parser::parse /tmp/repos/ripgrep` ALSO returned
//! `crates/core/flags/config.rs:parse` (a top-level function with the
//! same name) because the matcher dropped the `Parser::` qualifier and
//! accepted every bare `parse` candidate.
//!
//! The root cause: when the user types `Type::method`, the impact
//! pipeline falls through to the AST fallback (`find_function_in_ast`),
//! and the rust extractor for `extract_methods` emits only the bare
//! method name `parse` for every `impl ... { fn parse(...) { ... } }`
//! block, with no enclosing-type qualifier. The symmetric matcher
//! (`names_match`) then happily matches the qualified target against
//! every bare `parse` candidate via the "target qualified, candidate
//! bare, tail equal" direction.
//!
//! Fix
//! ---
//! Two parts:
//!
//! 1. `names_match` now refuses to fall through to the bare/tail
//!    relaxations when the target uses the `::` separator (canonically
//!    Rust/C++/Scala). For `::`-qualified targets we require either an
//!    exact match OR a candidate whose qualifier ends with the
//!    user-typed qualifier — preserving the "qualifier preserved" rule.
//!
//! 2. `find_function_in_ast` now walks `impl <Type> { ... }` blocks
//!    when the target is a Rust `::` qualifier and emits the qualified
//!    `<Type>::<method>` form so the AST-fallback can answer with the
//!    qualifier intact (impact/whatbreaks/context all key off this).
//!
//! Scope guard: the fix is limited to the canonical `impl Type::method`
//! form. The fully-qualified `<MyType as Trait>::method` form is
//! deferred to a follow-up.

use assert_cmd::prelude::*;
use serde_json::Value;
use std::process::Command;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

fn ripgrep_available() -> bool {
    std::path::Path::new("/tmp/repos/ripgrep/crates/globset/src/glob.rs").exists()
}

/// VAL-RUST-QUAL part-1: `tldr impact Parser::parse` must resolve ONLY to
/// `parse` methods that live inside `impl <something>Parser<...> { ... }`
/// blocks (in ripgrep that's two distinct `Parser` types — in
/// `crates/globset/src/glob.rs` and `crates/core/flags/parse.rs`).
/// Pre-fix the result ALSO contained `crates/core/flags/config.rs:parse`
/// — a top-level function in a parse-themed module that has no `Parser`
/// impl at all.
#[test]
fn rust_impact_glob_parse_only_returns_glob_impl_callers() {
    if !ripgrep_available() {
        eprintln!("skipping: /tmp/repos/ripgrep not available");
        return;
    }

    let mut cmd = tldr_cmd();
    cmd.args(["impact", "Parser::parse", "/tmp/repos/ripgrep", "-q"]);
    let out = cmd.assert().success().get_output().stdout.clone();
    let v: Value =
        serde_json::from_slice(&out).expect("impact output is not valid JSON");

    let targets = v
        .get("targets")
        .and_then(|t| t.as_object())
        .expect("targets{} missing");

    // The bad/pre-fix result included `crates/core/flags/config.rs:parse`
    // — a top-level `fn parse` that is NOT inside any `impl Parser` block.
    // Post-fix this key MUST NOT be present.
    let bad: Vec<&String> = targets
        .keys()
        .filter(|k| k.contains("flags/config.rs"))
        .collect();
    assert!(
        bad.is_empty(),
        "impact Parser::parse must not include top-level `parse` in \
         `flags/config.rs` (no `impl Parser` there); offending: {bad:?}; \
         full output: {v:#}"
    );

    // At least one valid target must exist (Parser::parse lives in
    // glob.rs and in flags/parse.rs).
    assert!(
        !targets.is_empty(),
        "impact Parser::parse must resolve at least one target; got {v:#}"
    );

    // Every resolved target MUST preserve the `Parser::` qualifier in
    // either the key or the function field.
    for (key, val) in targets {
        let func = val
            .get("function")
            .and_then(|f| f.as_str())
            .unwrap_or("");
        let preserves_qualifier =
            key.contains("Parser::parse") || func == "Parser::parse";
        assert!(
            preserves_qualifier,
            "impact target `{key}` (function `{func}`) dropped the \
             `Parser::` qualifier; full output: {v:#}"
        );
    }
}

/// VAL-RUST-QUAL part-2: `tldr whatbreaks Parser::parse` must resolve
/// strictly fewer targets than the bare `tldr impact parse` call — the
/// qualifier should *narrow* the result, not be silently dropped to a
/// superset.
#[test]
fn rust_whatbreaks_glob_parse_qualified() {
    if !ripgrep_available() {
        eprintln!("skipping: /tmp/repos/ripgrep not available");
        return;
    }

    // Baseline: bare `parse` (no qualifier) — should hit every parse.
    let mut bare_cmd = tldr_cmd();
    bare_cmd.args(["impact", "parse", "/tmp/repos/ripgrep", "-q"]);
    let bare_out = bare_cmd.assert().success().get_output().stdout.clone();
    let bare_v: Value =
        serde_json::from_slice(&bare_out).expect("bare impact output is not valid JSON");
    let bare_targets = bare_v
        .get("targets")
        .and_then(|t| t.as_object())
        .map(|o| o.len())
        .unwrap_or(0);

    // Qualified: `Parser::parse` — must be a STRICT subset.
    let mut qualified_cmd = tldr_cmd();
    qualified_cmd.args([
        "whatbreaks",
        "Parser::parse",
        "/tmp/repos/ripgrep",
        "-q",
    ]);
    let qual_out = qualified_cmd
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let qual_v: Value =
        serde_json::from_slice(&qual_out).expect("whatbreaks output is not valid JSON");

    // whatbreaks wraps an impact sub-result. Pull the impact target count.
    let sub_targets = qual_v
        .pointer("/sub_results/impact/data/report/targets")
        .and_then(|t| t.as_object())
        .map(|o| o.len())
        .or_else(|| {
            qual_v
                .pointer("/sub_results/impact/data/targets")
                .and_then(|t| t.as_u64())
                .map(|n| n as usize)
        })
        .expect("whatbreaks output missing sub_results/impact/data targets");

    assert!(
        sub_targets > 0,
        "whatbreaks Parser::parse must resolve at least one target; got 0; \
         full output: {qual_v:#}"
    );
    assert!(
        sub_targets < bare_targets,
        "whatbreaks Parser::parse ({sub_targets} targets) must be a strict \
         subset of the bare `parse` impact ({bare_targets} targets) — qualifier \
         should narrow, not drop. Full output: {qual_v:#}"
    );
}

/// VAL-RUST-QUAL part-3: `tldr context "<file>:Parser::parse"` must
/// resolve the qualified entry point and report a function whose name
/// preserves the `Parser::` qualifier — and the resolved entry must
/// live in `globset/src/glob.rs`, not a same-named function elsewhere.
#[test]
fn rust_context_glob_parse_qualified_resolves() {
    if !ripgrep_available() {
        eprintln!("skipping: /tmp/repos/ripgrep not available");
        return;
    }

    let entry = "/tmp/repos/ripgrep/crates/globset/src/glob.rs:Parser::parse";
    let mut cmd = tldr_cmd();
    cmd.args(["context", entry, "-q"]);
    let out = cmd.assert().success().get_output().stdout.clone();
    let v: Value =
        serde_json::from_slice(&out).expect("context output is not valid JSON");

    let funcs = v
        .get("functions")
        .and_then(|f| f.as_array())
        .expect("functions[] missing in context output");
    assert!(
        !funcs.is_empty(),
        "context Parser::parse must resolve at least one function; got {v:#}"
    );

    // Every emitted function must live in glob.rs AND preserve the
    // qualifier in its name. Pre-fix the qualifier was dropped
    // (`name: "parse"`).
    for f in funcs {
        let name = f.get("name").and_then(|n| n.as_str()).unwrap_or("");
        let file = f.get("file").and_then(|n| n.as_str()).unwrap_or("");
        assert!(
            file.contains("globset/src/glob.rs"),
            "context Parser::parse resolved a function in unrelated file \
             `{file}`; function name: `{name}`; full output: {v:#}"
        );
        assert!(
            name == "Parser::parse" || name.ends_with("::parse"),
            "context Parser::parse must preserve the qualifier in the name; \
             got `{name}`; full output: {v:#}"
        );
    }
}
