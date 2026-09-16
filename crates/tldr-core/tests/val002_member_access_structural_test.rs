//! M2 VAL-002 — AST member-access matching MUST be structural, not substring.
//!
//! Pre-fix: the 3 detect_*_ast predicates use `text.contains(member_pattern)`
//! which produces false positives whenever an arbitrary AST node's text happens
//! to include the pattern as a substring (e.g., a string literal containing
//! "req.body").
//!
//! Post-fix: predicates dispatch through
//! `extract_member_access_receiver_and_field` which uses
//! `field_access_info(language)` to match only on real member-access nodes.
//!
//! Plus REGRESSION-GUARD test: TypeScript framework sinks (NextJS / Fastify /
//! NestJS) added to the regex banks in v0.2.3 M3 MUST still fire under M2's
//! additive sink dispatch (option (c) — dispatch flip deferred to v0.4.0).
//! This is the test gap surfaced by the m2-ground-truth scout: ZERO existing
//! integration tests exercised compute_taint_with_tree() for any framework.

use std::collections::HashMap;

use tldr_core::ast::parser::parse;
use tldr_core::cfg::get_cfg_context;
use tldr_core::dfg::get_dfg_context;
use tldr_core::security::taint::{compute_taint_with_tree, detect_sources_ast};
use tldr_core::ssa::construct::construct_minimal_ssa;
use tldr_core::{compute_taint, Language, TaintInfo};

fn statements_from(src: &str) -> HashMap<u32, String> {
    src.lines()
        .enumerate()
        .map(|(i, text)| ((i + 1) as u32, text.to_string()))
        .collect()
}

fn analyze(src: &str, lang: Language, fn_name: &str) -> TaintInfo {
    analyze_with_ssa(src, lang, fn_name, /* use_ssa */ true)
}

fn analyze_with_ssa(src: &str, lang: Language, fn_name: &str, use_ssa: bool) -> TaintInfo {
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

/// Negative case (RED before fix): the AST detection path must NOT register a
/// source from a substring inside a string literal.
///
/// Pre-M2 the substring path `text.contains("req.body")` walked the
/// `lexical_declaration` node whose text included the string literal content,
/// matched on `"req.body"`, and registered a false-positive HttpBody source
/// (var=`message`).
///
/// Post-M2 the structural matcher only fires on `member_expression` nodes
/// (per `field_access_info` for TypeScript). Line 2 contains no
/// `member_expression`, only a `string` node — `detect_sources_ast` returns
/// empty.
///
/// This test calls `detect_sources_ast` directly (rather than the full
/// `compute_taint_with_tree`) because per option (c) the source dispatch at
/// `taint.rs:3429-3433` is AST-preferring with regex fallback — when AST
/// returns empty for a line, the regex bank still runs and, in v0.3.0, still
/// substring-matches `req\.body` against raw line text. Closing that
/// regex-side gap is deferred to v0.4.0 alongside the sink-parity work
/// documented in the M5 design doc §7. This test guards the AST path's
/// structural correctness independently.
#[test]
fn member_access_does_not_match_substring_in_string_literal_ts() {
    let src = "\
function handler() {
    const message = \"see req.body for details\";
    console.log(message);
}
";
    let tree = parse(src, Language::TypeScript).expect("TS parse");
    let root = tree.root_node();
    let ast_sources = detect_sources_ast(&root, src.as_bytes(), Language::TypeScript, None);
    assert!(
        ast_sources.is_empty(),
        "expected zero AST sources from string-literal substring 'req.body', got {} ({:?})",
        ast_sources.len(),
        ast_sources
    );
}

/// Positive: real member-access still detects after structural rewrite.
///
/// Uses the M1a fallback path (SSA disabled) for end-to-end flow construction
/// because the M1b SSA branch's flow-construction post-condition is exercised
/// by `val001b_ssa_versioned_taint_test::taint_falls_back_to_varref_when_ssa_unavailable`
/// — there's no need for M2 to re-litigate SSA semantics. M2's invariant is
/// solely that the AST member-access predicate registers `req.body` as a
/// HttpBody source structurally and that flow propagation through the M1a
/// path connects it to the `eval(x)` sink.
#[test]
fn member_access_still_detects_real_use_ts() {
    let src = "\
function handler(req, res) {
    let x = req.body;
    eval(x);
}
";
    let result = analyze_with_ssa(
        src,
        Language::TypeScript,
        "handler",
        /* use_ssa */ false,
    );
    assert!(
        !result.sources.is_empty(),
        "regression: real req.body member-access not detected post-M2; sources={:?}",
        result.sources
    );
    assert!(
        !result.flows.is_empty(),
        "regression: req.body -> eval flow not detected post-M2; sources={:?}, sinks={:?}, flows={:?}",
        result.sources,
        result.sinks,
        result.flows
    );
}

/// Python coverage: request.args is a member-access (attribute) node and must
/// still match after the structural rewrite.
#[test]
fn member_access_python_request_args() {
    let src = "\
def handler():
    data = request.args
    eval(data)
";
    let result = analyze(src, Language::Python, "handler");
    assert!(
        !result.sources.is_empty(),
        "request.args (member access) must register as source; sources={:?}",
        result.sources
    );
}

/// REGRESSION GUARD (option c): TypeScript NestJS framework sinks added to the
/// regex bank in v0.2.3 M3 MUST still fire post-M2. Sink dispatch is ADDITIVE
/// in v0.3.0 (regex+AST merged); the regex path catches NestJS even though
/// the AST bank doesn't have it. This test ensures M2 doesn't accidentally
/// flip dispatch.
#[test]
fn ts_framework_sinks_still_detected_post_m2() {
    let src = "\
function handler(req, res) {
    const data = req.body;
    res.redirect(data);
}
";
    let result = analyze(src, Language::TypeScript, "handler");
    // res.redirect on line 3 must be detected as a sink (covered by NestJS regex).
    let line3_sinks: Vec<_> = result.sinks.iter().filter(|s| s.line == 3).collect();
    assert!(
        !line3_sinks.is_empty(),
        "regression: NestJS res.redirect sink (added in v0.2.3 M3) lost. \
         Got sinks: {:?}",
        result.sinks
    );
}

/// Sanity: regex fallback path works when tree is None (no AST available).
/// Guards against any accidental change to the regex-only path that would
/// break callers without parsed trees.
#[test]
fn regex_fallback_works_without_tree() {
    let src = "\
def handler():
    data = request.args
    eval(data)
";
    let cfg = get_cfg_context(src, "handler", Language::Python).expect("cfg");
    let dfg = get_dfg_context(src, "handler", Language::Python).expect("dfg");
    let result = compute_taint(&cfg, &dfg.refs, &statements_from(src), Language::Python)
        .expect("regex fallback taint must succeed");
    assert!(
        !result.flows.is_empty(),
        "regex fallback (compute_taint, no tree) must still detect request.args -> eval flow; \
         flows={:?}, sources={:?}, sinks={:?}",
        result.flows,
        result.sources,
        result.sinks
    );
}
