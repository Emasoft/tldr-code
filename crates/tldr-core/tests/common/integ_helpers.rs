//! regex-removal-v1 — shared integration-test helpers.
//!
//! Extracted in W1.5-M6 from the inline duplicate copies in
//! `rr_framework_integ_test.rs`, `rr_stdlib_integ_test.rs`, and the seed
//! `val002_member_access_structural_test.rs`. Provides a single source of
//! truth for the analyze() pipeline used by every Wave-1.5+ integration
//! test:
//!
//!   parse → CFG → DFG → SSA (optional) → compute_taint_with_tree
//!
//! Helper signatures match the originals exactly — refactor is shape-
//! preserving. This file is loaded into integration-test crates via
//! `#[path = "common/integ_helpers.rs"] mod common;` (mirroring the
//! `#[path = "support/..."] mod support;` convention already used by
//! `surface_language_profile_tests.rs`).
//!
//! Cargo also auto-treats `tests/common/mod.rs` as a non-test module; we
//! avoid that path to stay consistent with the existing repo convention
//! and to keep the helper file name explicit per the W1.5-M6 dispatch
//! contract.

#![allow(dead_code)]

use std::collections::HashMap;

use tldr_core::ast::parser::parse;
use tldr_core::cfg::get_cfg_context;
use tldr_core::dfg::get_dfg_context;
use tldr_core::security::taint::{compute_taint_with_tree, AstOnlyTestModeGuard};
use tldr_core::ssa::construct::construct_minimal_ssa;
use tldr_core::{Language, TaintInfo, TaintSinkType, TaintSourceType};

/// Build a `HashMap<line_no, statement_text>` from raw source. Line numbers
/// are 1-indexed to match tree-sitter and the rest of the taint pipeline.
pub fn statements_from(src: &str) -> HashMap<u32, String> {
    src.lines()
        .enumerate()
        .map(|(i, text)| ((i + 1) as u32, text.to_string()))
        .collect()
}

/// SSA-on convenience wrapper. Mirrors the original
/// `val002::analyze` signature: parse + CFG + DFG + SSA + taint.
pub fn analyze(src: &str, lang: Language, fn_name: &str) -> TaintInfo {
    analyze_with_ssa(src, lang, fn_name, /* use_ssa */ true)
}

/// Full pipeline with explicit SSA toggle. SSA-off is occasionally needed
/// for tests that exercise the M1a flow-construction path consistent with
/// `val002::member_access_still_detects_real_use_ts`.
pub fn analyze_with_ssa(src: &str, lang: Language, fn_name: &str, use_ssa: bool) -> TaintInfo {
    let cfg = get_cfg_context(src, fn_name, lang).expect("CFG must succeed");
    let dfg = get_dfg_context(src, fn_name, lang).expect("DFG must succeed");
    let ssa = if use_ssa {
        construct_minimal_ssa(&cfg, &dfg).ok()
    } else {
        None
    };
    let tree = parse(src, lang).expect("parse must succeed");

    compute_taint_with_tree(
        &cfg,
        &dfg.refs,
        &statements_from(src),
        Some(&tree),
        Some(src.as_bytes()),
        lang,
        ssa.as_ref(),
    )
    .expect("taint analysis must succeed")
}

/// AST-only dispatch harness — transiently empties the regex `.sources` /
/// `.sinks` / `.sanitizers` banks for the target language by activating the
/// thread-local `AstOnlyTestModeGuard` defined in
/// `tldr_core::security::taint`. While the guard is alive, `detect_sources`
/// / `detect_sinks` / `detect_sanitizer` short-circuit to empty
/// vectors / `None` regardless of the regex banks' contents, so the only
/// detection paths that can produce sources/sinks/sanitizers are the AST
/// paths inside `compute_taint_with_tree` (`detect_sources_ast` /
/// `detect_sinks_ast` / `detect_sanitizer_ast`).
///
/// Note: extension to sanitizers added in `sanitizer-removal-v1` M1 — the
/// 3-LOC `AST_ONLY_TEST_MODE` short-circuit at `taint.rs:1096`
/// (`detect_sanitizer`) mirrors the existing `detect_sources` (L816-818)
/// and `detect_sinks` (L933-935) checks. Used as the RED gate for
/// `sanitizer-removal-v1` M2/M3/M4.
///
/// Mirrors the W2-pre "AST-only mode simulation" pattern proven in
/// `regex-removal-v1` (W2-pre-report.json:45 — "Temporarily disabled regex
/// fallback in compute_taint_with_tree (then restored before commit). Re-ran
/// all 34 tests: 34/34 PASS under AST-only dispatch."). Used as the
/// discriminative RED gate for `field_access_info-extension-v1` M2/M3/M4:
/// fixtures asserting under this helper FAIL at HEAD pre-M2 because the
/// raw-substring `("", "Module.fn")` AST entries are skipped by the
/// structural and W2-pre call-shape paths. M2/M3/M4 turn them GREEN by
/// rewriting the entries to structured `("Module", "fn")` shape.
///
/// Always runs with SSA off — the M1 fixtures don't need SSA precision and
/// running without SSA matches the per-language baseline tests' convention.
pub fn analyze_ast_only(src: &str, lang: Language, fn_name: &str) -> TaintInfo {
    let _guard = AstOnlyTestModeGuard::enter();
    analyze_with_ssa(src, lang, fn_name, /* use_ssa */ false)
}

/// Assert that `result` contains at least one source of `expected_source`,
/// at least one `CodeEval` sink, and at least one source→sink flow.
///
/// Used by the W1-M5 framework source tests and the W1.5-M6 baseline
/// per-language tests when the fixture targets `eval(...)` as the sink.
pub fn assert_source_to_eval_flow(result: &TaintInfo, expected_source: TaintSourceType) {
    let source_match = result
        .sources
        .iter()
        .any(|s| s.source_type == expected_source);
    assert!(
        source_match,
        "expected at least one {:?} source; got sources={:?}",
        expected_source, result.sources
    );
    let eval_sinks: Vec<_> = result
        .sinks
        .iter()
        .filter(|s| matches!(s.sink_type, TaintSinkType::CodeEval))
        .collect();
    assert!(
        !eval_sinks.is_empty(),
        "expected at least one CodeEval sink; got sinks={:?}",
        result.sinks
    );
    assert!(
        !result.flows.is_empty(),
        "expected at least one source->sink flow; got flows={:?}",
        result.flows
    );
}

/// Assert that `result` contains at least one sink of `expected_sink`.
/// Returns the matching sink line numbers for further assertions.
///
/// Used by category-C baseline tests to express
/// "at least one ShellExec / CodeEval / FileWrite sink at <line>".
pub fn assert_has_sink_of_type(result: &TaintInfo, expected_sink: TaintSinkType) -> Vec<u32> {
    let lines: Vec<u32> = result
        .sinks
        .iter()
        .filter(|s| s.sink_type == expected_sink)
        .map(|s| s.line)
        .collect();
    assert!(
        !lines.is_empty(),
        "expected at least one {:?} sink; got sinks={:?}",
        expected_sink,
        result.sinks
    );
    lines
}
