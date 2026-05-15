//! v0.4.2 M-015 — debt SQALE wiring across languages.
//!
//! Before this fix `tldr debt` reported `total_minutes: 0` (or only
//! TODO-comment debt) for many languages because the function-info
//! extractor only handled Python/TS/JS/Go/Rust/Java. Smells, cognitive
//! complexity and Halstead violations were not routed through the SQALE
//! mapper for C, C#, Elixir, Kotlin, Lua, Luau, OCaml, Ruby, etc.
//!
//! The `language` field on the report was also unconditionally `null`
//! when no `--language` flag was supplied even though every analyzed
//! file had a detectable language.
//!
//! This test pins the *post-fix* contract:
//!
//!   1. For a fixture containing TODO + complexity + deep-nesting + long
//!      method + long parameter list, the per-language `tldr debt` run
//!      reports a positive `total_minutes` AND a non-empty
//!      `by_category` breakdown (`reliability` + `maintainability` at
//!      minimum).
//!   2. The top-level `language` field is populated (non-null) when the
//!      command is run against a single file with a detectable
//!      extension, mirroring the contract already documented for
//!      `tldr clones`.
//!
//! Fixtures are written into a temp dir so the test is hermetic.

use std::process::Command;

use serde_json::Value;
use tempfile::TempDir;

/// Resolve the `tldr` binary path. Honors `CARGO_BIN_EXE_tldr` (set by
/// `cargo test`); falls back to the workspace `target/release/tldr` so
/// the test can also be run directly via `cargo test --release` /
/// `cargo nextest` from the repo root.
fn tldr_bin() -> String {
    if let Some(p) = option_env!("CARGO_BIN_EXE_tldr") {
        return p.to_string();
    }
    // Fallback: assume workspace root + target/release/tldr
    let manifest = env!("CARGO_MANIFEST_DIR");
    let workspace_root = std::path::Path::new(manifest)
        .parent()
        .and_then(|p| p.parent())
        .unwrap_or_else(|| std::path::Path::new("."));
    workspace_root
        .join("target/release/tldr")
        .display()
        .to_string()
}

fn run_debt(path: &std::path::Path) -> Value {
    let out = Command::new(tldr_bin())
        .arg("debt")
        .arg(path)
        .arg("--format")
        .arg("json")
        .output()
        .expect("failed to spawn tldr debt");
    let stdout = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "debt output was not valid JSON for {}: {}\nstdout: {}\nstderr: {}",
            path.display(),
            e,
            stdout,
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

/// Source containing TODO + 7-param func + deep nesting + long method,
/// instantiated per-language so we exercise the universal extractor.
struct Fixture {
    filename: &'static str,
    body: &'static str,
    expected_language: &'static str,
}

const FIXTURES: &[Fixture] = &[
    Fixture {
        filename: "big.kt",
        body: include_str!("debt_sqale_fixtures/big.kt"),
        expected_language: "kotlin",
    },
    Fixture {
        filename: "big.rb",
        body: include_str!("debt_sqale_fixtures/big.rb"),
        expected_language: "ruby",
    },
    Fixture {
        filename: "big.c",
        body: include_str!("debt_sqale_fixtures/big.c"),
        expected_language: "c",
    },
    Fixture {
        filename: "big.cs",
        body: include_str!("debt_sqale_fixtures/big.cs"),
        expected_language: "csharp",
    },
    Fixture {
        filename: "big.lua",
        body: include_str!("debt_sqale_fixtures/big.lua"),
        expected_language: "lua",
    },
    Fixture {
        filename: "big.ex",
        body: include_str!("debt_sqale_fixtures/big.ex"),
        expected_language: "elixir",
    },
];

#[test]
fn debt_total_minutes_positive_across_langs() {
    let tmp = TempDir::new().expect("tempdir");
    for fx in FIXTURES {
        let p = tmp.path().join(fx.filename);
        std::fs::write(&p, fx.body).expect("write fixture");
        let report = run_debt(&p);
        let total = report
            .pointer("/summary/total_minutes")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        // Each fixture has at least: a TODO (10) + a smell (15/20/30) so
        // a minimum of ~25 minutes is the floor. We allow >= 30 to give
        // a margin while still catching the pre-fix `0 / 10` regressions.
        assert!(
            total >= 30,
            "{}: expected debt.summary.total_minutes >= 30, got {}. Full report:\n{}",
            fx.filename,
            total,
            serde_json::to_string_pretty(&report).unwrap()
        );
    }
}

#[test]
fn debt_emits_both_reliability_and_maintainability_categories() {
    let tmp = TempDir::new().expect("tempdir");
    for fx in FIXTURES {
        let p = tmp.path().join(fx.filename);
        std::fs::write(&p, fx.body).expect("write fixture");
        let report = run_debt(&p);
        let by_cat = report
            .pointer("/summary/by_category")
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("{}: missing by_category", fx.filename));
        assert!(
            by_cat.contains_key("reliability"),
            "{}: by_category missing `reliability` (TODO mapping). by_category={:?}",
            fx.filename,
            by_cat
        );
        assert!(
            by_cat.contains_key("maintainability"),
            "{}: by_category missing `maintainability` (complexity/deep-nesting/long-method mapping). by_category={:?}",
            fx.filename,
            by_cat
        );
    }
}

#[test]
fn debt_top_level_language_field_populated_when_detectable() {
    let tmp = TempDir::new().expect("tempdir");
    for fx in FIXTURES {
        let p = tmp.path().join(fx.filename);
        std::fs::write(&p, fx.body).expect("write fixture");
        let report = run_debt(&p);
        let lang = report
            .get("language")
            .and_then(Value::as_str)
            .unwrap_or_else(|| {
                panic!(
                    "{}: top-level `language` was null or missing; expected `{}`. Full report:\n{}",
                    fx.filename,
                    fx.expected_language,
                    serde_json::to_string_pretty(&report).unwrap()
                )
            });
        assert_eq!(
            lang, fx.expected_language,
            "{}: expected language `{}`, got `{}`",
            fx.filename, fx.expected_language, lang
        );
    }
}

#[test]
fn debt_emits_per_function_issue_with_element_field_across_langs() {
    // Smoke test that we get function-level issues (not just file-level
    // TODOs) for the non-Python/JS langs. Pre-fix these were all
    // dropped on the floor.
    let tmp = TempDir::new().expect("tempdir");
    for fx in FIXTURES {
        let p = tmp.path().join(fx.filename);
        std::fs::write(&p, fx.body).expect("write fixture");
        let report = run_debt(&p);
        let issues = report
            .get("issues")
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("{}: missing issues array", fx.filename));
        let has_func_issue = issues.iter().any(|i| {
            i.get("element").and_then(Value::as_str).is_some()
                && matches!(
                    i.get("rule").and_then(Value::as_str),
                    Some(
                        "complexity.high"
                            | "complexity.very_high"
                            | "complexity.extreme"
                            | "cognitive.high"
                            | "cognitive.very_high"
                            | "cognitive.extreme"
                            | "long_method"
                            | "long_param_list"
                            | "deep_nesting"
                            | "halstead_high"
                    )
                )
        });
        assert!(
            has_func_issue,
            "{}: expected at least one function-level debt issue (complexity / long_method / long_param_list / deep_nesting / cognitive / halstead). Got: {:#?}",
            fx.filename, issues
        );
    }
}
