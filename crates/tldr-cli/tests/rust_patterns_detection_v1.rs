//! rust-patterns-detection-v1 (v0.4.2 bug-C4 / VAL-RUST-PATTERNS)
//!
//! Pre-fix audit assertion (W-M dispatch contract):
//! > "`tldr patterns /tmp/repos/ripgrep` returns 0 patterns across 100
//! >  rust files. ripgrep visibly uses Builder pattern, Visitor pattern,
//! >  and possibly others. The rust adapter is either disabled or
//! >  pattern-detector signatures don't match rust idiom."
//!
//! Audit-clarification verdict: MEASUREMENT ARTIFACT.
//!
//! 1. `tldr patterns /tmp/repos/ripgrep` already returns three rust
//!    patterns in production: `result_type`, `question_mark_operator`,
//!    `custom_errors`. The `metadata.language_distribution.patterns_by_language`
//!    map shows `rust: 3`, not zero. The "0 patterns" claim in the
//!    audit text appears to be a misread of the output (perhaps from
//!    looking only at GoF design-pattern keys, which the command does
//!    not emit for ANY language).
//!
//! 2. The `patterns` command is NOT a GoF design-pattern detector.
//!    Per `crates/tldr-cli/src/commands/patterns/spec.md`, it analyses
//!    **code-style and behavioural idioms**: error_handling, naming,
//!    resource_management, import_patterns, api_conventions,
//!    soft_delete, async_patterns, test_idioms. There is no Builder /
//!    Visitor / Observer catalogue to "enable" — the framework was
//!    never claimed to detect those.
//!
//! 3. The Rust adapter is fully wired in
//!    `crates/tldr-core/src/patterns/language_profile.rs`:
//!      - `language_profile()` returns `Some(LanguageProfile { … })` for
//!        `Language::Rust` at line ~1427.
//!      - `RustSemantics::process_node` dispatches on `function_item`,
//!        `impl_item`, `enum_item`, `struct_item`, `use_declaration`,
//!        `const_item`, `static_item` (lines 1037–1067).
//!      - Helpers populate signals for function naming, async, Result
//!        types, `impl Drop`, error enums (`*Error` / `*Err`), soft
//!        delete fields, `Mutex<T>` / `RwLock<T>` / `mpsc::` / `channel`,
//!        tokio usage, relative vs absolute `use`, const naming.
//!    This is broader coverage than the Java adapter (lines 1229–1268),
//!    which only does class + method naming.
//!
//! Therefore this file is a **regression guard**, not a bug fix. It
//! pins three invariants so a future refactor of the dispatch table or
//! semantics impl cannot silently re-introduce a real "0 patterns on
//! rust" regression.
//!
//! Real-repo gated per no-synthetic-fixtures-v1: each test returns
//! early when its `/tmp/repos/<repo>` corpus is absent.

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

const RG_CORPUS: &str = "/tmp/repos/ripgrep";
const PETCLINIC_CORPUS: &str = "/tmp/repos/spring-petclinic";

// ============================================================================
// TEST 1: `tldr patterns <rust-repo>` must report a non-zero pattern count
//         for rust under `metadata.language_distribution.patterns_by_language`.
//
//         This is the literal contradiction of the audit claim. If this
//         fails, the rust adapter has genuinely been broken — either the
//         `language_profile()` arm has been removed, or the dispatch table
//         in `rust_node_map()` has been emptied, or `RustSemantics` no
//         longer pushes signals.
// ============================================================================
#[test]
fn rust_patterns_detects_at_least_one() {
    if !Path::new(RG_CORPUS).exists() {
        eprintln!(
            "[skip] rust_patterns_detects_at_least_one: corpus {} not present",
            RG_CORPUS
        );
        return;
    }

    let (rc, out) = run_tldr(&["patterns", RG_CORPUS, "--format", "json"]);
    assert_eq!(rc, 0, "patterns must succeed on ripgrep; got rc={}", rc);

    let v = parse_json(&out);
    let by_lang = &v["metadata"]["language_distribution"]["patterns_by_language"];
    assert!(
        by_lang.is_object(),
        "patterns_by_language must be an object; got {:?}",
        by_lang
    );

    let rust_count = by_lang["rust"].as_u64().unwrap_or(0);
    assert!(
        rust_count >= 1,
        "rust pattern count must be >= 1 on ripgrep; got {} \
         (audit claim was 0 — if this fires the rust adapter has \
         actually regressed). Full patterns_by_language: {:?}",
        rust_count,
        by_lang
    );

    // Also make sure ripgrep was actually scanned as rust (i.e. the
    // file-level language classification is not the regressed surface).
    let files_by_lang = &v["metadata"]["language_distribution"]["files_by_language"];
    let rust_files = files_by_lang["rust"].as_u64().unwrap_or(0);
    assert!(
        rust_files >= 50,
        "ripgrep must classify >= 50 rust files; got {}. files_by_language: {:?}",
        rust_files,
        files_by_lang
    );
}

// ============================================================================
// TEST 2: at least one detected pattern on ripgrep must come from the
//         rust-specific signal pipeline. We assert this structurally by
//         requiring `error_handling` to be present with rust-flavoured
//         patterns (`result_type` and/or `question_mark_operator`).
//
//         These two pattern *names* are emitted only by the rust
//         error-handling rollup (see
//         `crates/tldr-core/src/patterns/error_handling.rs`). Their
//         appearance proves the rust adapter populated `signals.error_handling`
//         end-to-end: Result return types via `RustSemantics::detect_function`
//         and `?` ops via the `try_expression` dispatch entry in
//         `rust_node_map()`. The audit text named "Builder" — but Builder
//         is not a key the framework emits for any language. The closest
//         analogue ("an idiomatic rust pattern present in ripgrep") is
//         `result_type` / `question_mark_operator`.
// ============================================================================
#[test]
fn rust_patterns_detects_idiomatic_rust_signal() {
    if !Path::new(RG_CORPUS).exists() {
        eprintln!(
            "[skip] rust_patterns_detects_idiomatic_rust_signal: corpus {} not present",
            RG_CORPUS
        );
        return;
    }

    let (rc, out) = run_tldr(&["patterns", RG_CORPUS, "--format", "json"]);
    assert_eq!(rc, 0, "patterns must succeed on ripgrep; got rc={}", rc);

    let v = parse_json(&out);
    let eh = &v["error_handling"];
    assert!(
        eh.is_object(),
        "ripgrep must surface an error_handling block; got {:?}. \
         If absent, RustSemantics::detect_function is no longer pushing \
         to signals.error_handling.result_types, or the rollup thresholds \
         have been raised above what ripgrep can hit.",
        eh
    );

    let patterns = eh["patterns"].as_array().cloned().unwrap_or_default();
    let names: Vec<String> = patterns
        .iter()
        .filter_map(|p| p.as_str().map(|s| s.to_string()))
        .collect();

    let has_rust_idiom = names.iter().any(|n| {
        n == "result_type" || n == "question_mark_operator" || n == "custom_errors"
    });
    assert!(
        has_rust_idiom,
        "ripgrep error_handling.patterns must include at least one of \
         [result_type, question_mark_operator, custom_errors] — got {:?}. \
         Pre-fix observation: all three were present.",
        names
    );
}

// ============================================================================
// TEST 3 (non-regression): `tldr patterns` on a java repo must still
//         work — and in particular must still report java naming
//         constraints. This guards against a future rust-adapter edit
//         accidentally short-circuiting the language-agnostic rollup.
// ============================================================================
#[test]
fn java_patterns_still_works() {
    if !Path::new(PETCLINIC_CORPUS).exists() {
        eprintln!(
            "[skip] java_patterns_still_works: corpus {} not present",
            PETCLINIC_CORPUS
        );
        return;
    }

    let (rc, out) = run_tldr(&["patterns", PETCLINIC_CORPUS, "--format", "json"]);
    assert_eq!(
        rc, 0,
        "patterns must succeed on spring-petclinic; got rc={}",
        rc
    );

    let v = parse_json(&out);
    let by_lang = &v["metadata"]["language_distribution"]["patterns_by_language"];
    let java_count = by_lang["java"].as_u64().unwrap_or(0);
    assert!(
        java_count >= 1,
        "java pattern count must be >= 1 on spring-petclinic; got {}. \
         patterns_by_language: {:?}",
        java_count,
        by_lang
    );

    let naming = &v["naming"];
    assert!(
        naming.is_object(),
        "java patterns must include a naming block on spring-petclinic; \
         got {:?}",
        naming
    );

    // Spring-petclinic uses idiomatic camelCase methods + PascalCase classes.
    let func_case = naming["functions"].as_str().unwrap_or("");
    let class_case = naming["classes"].as_str().unwrap_or("");
    assert_eq!(
        func_case, "camel_case",
        "java methods on spring-petclinic should be camel_case; got {:?}",
        func_case
    );
    assert_eq!(
        class_case, "pascal_case",
        "java classes on spring-petclinic should be pascal_case; got {:?}",
        class_case
    );
}
