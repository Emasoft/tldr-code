//! regex-removal-v1 — Wave 1 framework integration tests.
//!
//! These tests exercise the structural AST taint pipeline end-to-end via
//! `compute_taint_with_tree(...)` for framework patterns currently covered only
//! by regex banks. As parity-add milestones (W1-M1..M5) land, RED tests in this
//! file transition to GREEN; once Wave 2 deletes the regex banks, this file
//! becomes the primary safety net.
//!
//! Helper shape mirrored from
//! `val002_member_access_structural_test.rs::analyze` /
//! `analyze_with_ssa`. As of W1.5-M6 the `analyze` / `analyze_with_ssa` /
//! `assert_source_to_eval_flow` helpers live in
//! `tests/common/integ_helpers.rs` and are shared by every Wave-1.5+
//! integration test file (framework / stdlib / per-language baseline).
//!
//! Milestone scope:
//! * W1-M1 — NextJS sink AST entries (this file's first 4 tests).
//! * W1-M2 — Fastify sink AST entries (`reply.send` / `.redirect` / `.header`).
//! * W1-M3 — NestJS sink AST entries (`res.send|redirect|json` +
//!   `Response.send|redirect|json` builder forms).
//! * W1-M5 — NextJS+Fastify+NestJS source AST entries (request.json/text/
//!   formData/body/headers/cookies/params/query/raw + searchParams.* + 3
//!   raw-fallbacks for nextUrl/headers()/cookies() + 9 NestJS decorator
//!   raw-fallbacks). Source-side parity-add — exercises the full
//!   source→sink flow path through `compute_taint_with_tree`.
//! * W1.5-M6 — refactor only: helpers moved to `common/integ_helpers.rs`;
//!   the 18 tests below are unchanged.

use tldr_core::{Language, TaintInfo, TaintSinkType, TaintSourceType};

#[path = "common/integ_helpers.rs"]
mod common;

use common::{analyze_with_ssa, assert_source_to_eval_flow as common_assert_source_to_eval_flow};

// ---------- W1-M1: NextJS sinks ----------

/// W1-M1 #1 — `NextResponse.redirect(body.url)` where `body` came from
/// `request.json()`. Open-redirect via reflected URL.
///
/// Pre-W1-M1: AST bank lacks `('NextResponse','redirect')`; this test
/// fails (RED) when the regex bank is bypassed. After W1-M1 adds the entry,
/// `result.sinks` contains a `FileWrite` (per dispatch contract mapping)
/// at the `NextResponse.redirect(...)` line.
#[test]
fn nextjs_response_redirect_open_redirect_via_compute_taint() {
    let src = "\
export async function POST(request) {
    const body = await request.json();
    return NextResponse.redirect(body.url);
}
";
    // SSA disabled: keeps M1a flow-construction path consistent with val002's
    // `member_access_still_detects_real_use_ts` regression test.
    let result = analyze_with_ssa(src, Language::TypeScript, "POST", /* use_ssa */ false);
    let sink_lines: Vec<_> = result
        .sinks
        .iter()
        .filter(|s| matches!(s.sink_type, TaintSinkType::OpenRedirect))
        .map(|s| s.line)
        .collect();
    assert!(
        !sink_lines.is_empty(),
        "expected at least one OpenRedirect sink for NextResponse.redirect; \
         got sinks={:?}",
        result.sinks
    );
}

/// W1-M1 #2 — `NextResponse.json(data)` reflects `request.json()` body —
/// reflected XSS via response body.
///
/// detection-gap-fixes-v1: assertion CHANGED from `FileWrite` to `HtmlOutput`.
/// Pre-fix the test was orphaned: `js-res-json-fp-narrowing-v1` removed
/// `(NextResponse, json)` from the FileWrite bank (correct: NextResponse.json
/// is NOT a path-traversal sink), but no replacement HtmlOutput entry was
/// added — the test stayed RED with `result.sinks=[]`. The milestone closes
/// the gap by adding `(NextResponse, json)` to the HtmlOutput bank
/// (semantically: reflected user input emitted as a JSON response body that
/// downstream HTML-interpreting consumers may treat as XSS payload). The
/// test name (`..._reflected_xss_...`) already encodes the correct
/// classification — the assertion now matches the name.
#[test]
fn nextjs_response_json_reflected_xss_via_compute_taint() {
    let src = "\
export async function POST(request) {
    const data = await request.json();
    return NextResponse.json(data);
}
";
    let result = analyze_with_ssa(src, Language::TypeScript, "POST", /* use_ssa */ false);
    let sink_lines: Vec<_> = result
        .sinks
        .iter()
        .filter(|s| matches!(s.sink_type, TaintSinkType::HtmlOutput))
        .map(|s| s.line)
        .collect();
    assert!(
        !sink_lines.is_empty(),
        "expected at least one HtmlOutput sink for NextResponse.json; \
         got sinks={:?}",
        result.sinks
    );
}

/// W1-M1 #3 — server-action helper bare `redirect(url)` from
/// `next/navigation`. This is a bare CallExpression (no receiver) — covered
/// by raw-fallback `('', 'redirect')` member_pattern post-W1-M1.
#[test]
fn nextjs_redirect_helper_via_compute_taint() {
    let src = "\
import { redirect } from 'next/navigation';

export async function action(formData) {
    const url = formData.get('next');
    redirect(url);
}
";
    let result = analyze_with_ssa(
        src,
        Language::TypeScript,
        "action",
        /* use_ssa */ false,
    );
    let sink_lines: Vec<_> = result
        .sinks
        .iter()
        .filter(|s| matches!(s.sink_type, TaintSinkType::OpenRedirect))
        .map(|s| s.line)
        .collect();
    assert!(
        !sink_lines.is_empty(),
        "expected at least one OpenRedirect sink for bare redirect() helper; \
         got sinks={:?}",
        result.sinks
    );
}

/// W1-M1 #4 — JSX `dangerouslySetInnerHTML` attribute reflecting tainted
/// `params.html`. JSX attribute identifier match — covered by raw-fallback
/// `('', 'dangerouslySetInnerHTML')` member_pattern post-W1-M1.
#[test]
fn nextjs_dangerously_set_inner_html_via_compute_taint() {
    let src = "\
export default function Page({ params }) {
    const html = params.html;
    return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
";
    let result = analyze_with_ssa(src, Language::TypeScript, "Page", /* use_ssa */ false);
    let sink_lines: Vec<_> = result
        .sinks
        .iter()
        .filter(|s| matches!(s.sink_type, TaintSinkType::FileWrite))
        .map(|s| s.line)
        .collect();
    assert!(
        !sink_lines.is_empty(),
        "expected at least one FileWrite sink for dangerouslySetInnerHTML; \
         got sinks={:?}",
        result.sinks
    );
}

// ---------- W1-M2: Fastify sinks ----------

/// W1-M2 #1 — `reply.send(data)` reflects `request.body` — reflected
/// response from a Fastify handler. Pre-W1-M2: AST bank lacks
/// `('reply','send')`; the regex bank's FASTIFY_PATTERNS sink
/// `\breply\.send\s*\(` is what currently catches it. Post-W1-M2: matches
/// via TYPESCRIPT_AST_SINKS member_pattern.
#[test]
fn fastify_reply_send_reflected_via_compute_taint() {
    let src = "\
async function echo(request, reply) {
    const data = request.body;
    reply.send(data);
}
";
    let result = analyze_with_ssa(src, Language::TypeScript, "echo", /* use_ssa */ false);
    let sink_lines: Vec<_> = result
        .sinks
        .iter()
        .filter(|s| matches!(s.sink_type, TaintSinkType::HtmlOutput))
        .map(|s| s.line)
        .collect();
    assert!(
        !sink_lines.is_empty(),
        "expected at least one HtmlOutput sink for reply.send; \
         got sinks={:?}",
        result.sinks
    );
}

/// W1-M2 #2 — `reply.redirect(url)` where `url` is reflected from
/// `request.body.next` — open redirect via Fastify reply API.
#[test]
fn fastify_reply_redirect_via_compute_taint() {
    let src = "\
async function go(request, reply) {
    const target = request.body.next;
    reply.redirect(target);
}
";
    let result = analyze_with_ssa(src, Language::TypeScript, "go", /* use_ssa */ false);
    let sink_lines: Vec<_> = result
        .sinks
        .iter()
        .filter(|s| matches!(s.sink_type, TaintSinkType::OpenRedirect))
        .map(|s| s.line)
        .collect();
    assert!(
        !sink_lines.is_empty(),
        "expected at least one OpenRedirect sink for reply.redirect; \
         got sinks={:?}",
        result.sinks
    );
}

/// W1-M2 #3 — `reply.header('X-Echo', v)` where `v` came from
/// `request.headers['x-forwarded']` — header injection via Fastify reply.
#[test]
fn fastify_reply_header_injection_via_compute_taint() {
    let src = "\
async function setHeader(request, reply) {
    const v = request.headers['x-forwarded'];
    reply.header('X-Echo', v);
}
";
    let result = analyze_with_ssa(
        src,
        Language::TypeScript,
        "setHeader",
        /* use_ssa */ false,
    );
    let sink_lines: Vec<_> = result
        .sinks
        .iter()
        .filter(|s| matches!(s.sink_type, TaintSinkType::FileWrite))
        .map(|s| s.line)
        .collect();
    assert!(
        !sink_lines.is_empty(),
        "expected at least one FileWrite sink for reply.header; \
         got sinks={:?}",
        result.sinks
    );
}

// ---------- W1-M3: NestJS sinks ----------

/// W1-M3 #1 — `res.send(v)` reflects `req.body.v` — reflected XSS via the
/// Express-style `res` parameter NestJS controllers also expose. Pre-W1-M3:
/// AST bank lacks `('res','send')` (Express never wired it as a structural
/// entry); regex bank's `NESTJS_PATTERNS` sink `\bres\.(send|redirect|json)\s*\(`
/// catches it. Post-W1-M3: matches via `TYPESCRIPT_AST_SINKS` member_pattern.
#[test]
fn nestjs_res_send_reflected_via_compute_taint() {
    let src = "\
async function handler(req, res) {
    const v = req.body.v;
    res.send(v);
}
";
    let result = analyze_with_ssa(
        src,
        Language::TypeScript,
        "handler",
        /* use_ssa */ false,
    );
    let sink_lines: Vec<_> = result
        .sinks
        .iter()
        .filter(|s| matches!(s.sink_type, TaintSinkType::HtmlOutput))
        .map(|s| s.line)
        .collect();
    assert!(
        !sink_lines.is_empty(),
        "expected at least one HtmlOutput sink for res.send; \
         got sinks={:?}",
        result.sinks
    );
}

/// W1-M3 #2 — `res.redirect(next)` with `next` reflected from `req.query.next`
/// — open redirect via NestJS Express-style `res`.
#[test]
fn nestjs_res_redirect_open_redirect_via_compute_taint() {
    let src = "\
async function handler(req, res) {
    const next = req.query.next;
    res.redirect(next);
}
";
    let result = analyze_with_ssa(
        src,
        Language::TypeScript,
        "handler",
        /* use_ssa */ false,
    );
    let sink_lines: Vec<_> = result
        .sinks
        .iter()
        .filter(|s| matches!(s.sink_type, TaintSinkType::OpenRedirect))
        .map(|s| s.line)
        .collect();
    assert!(
        !sink_lines.is_empty(),
        "expected at least one OpenRedirect sink for res.redirect; \
         got sinks={:?}",
        result.sinks
    );
}

/// W1-M3 #3 — NestJS `Response`-builder form: `response.send(v)` where the
/// parameter is named `response` (capitalized-builder convention noted in the
/// dispatch contract). The receiver identifier `response` differs from the
/// Express-style `res`; covered post-W1-M3 by adding `('Response','send')` to
/// `TYPESCRIPT_AST_SINKS` (matched case-insensitively as a member pattern).
#[test]
fn nestjs_response_builder_send_via_compute_taint() {
    let src = "\
async function handler(req, response) {
    const v = req.body.v;
    response.send(v);
}
";
    let result = analyze_with_ssa(
        src,
        Language::TypeScript,
        "handler",
        /* use_ssa */ false,
    );
    let sink_lines: Vec<_> = result
        .sinks
        .iter()
        .filter(|s| matches!(s.sink_type, TaintSinkType::HtmlOutput))
        .map(|s| s.line)
        .collect();
    assert!(
        !sink_lines.is_empty(),
        "expected at least one HtmlOutput sink for Response.send (builder); \
         got sinks={:?}",
        result.sinks
    );
}

/// W1-M3 #4 — NestJS `Response`-builder form: `Response.redirect(next)` where
/// the parameter is named `Response` (capitalized identifier). This is
/// distinct from `NextResponse.redirect` (W1-M1) — NestJS docs use the
/// capitalized builder identifier. Post-W1-M3: covered via `('Response',
/// 'redirect')` in `TYPESCRIPT_AST_SINKS` (already added in W1-M1's NextJS
/// block; this test exercises that entry through a NestJS-shape fixture).
#[test]
fn nestjs_response_builder_redirect_via_compute_taint() {
    let src = "\
async function handler(req, Response) {
    const next = req.query.url;
    Response.redirect(next);
}
";
    let result = analyze_with_ssa(
        src,
        Language::TypeScript,
        "handler",
        /* use_ssa */ false,
    );
    let sink_lines: Vec<_> = result
        .sinks
        .iter()
        .filter(|s| matches!(s.sink_type, TaintSinkType::OpenRedirect))
        .map(|s| s.line)
        .collect();
    assert!(
        !sink_lines.is_empty(),
        "expected at least one OpenRedirect sink for Response.redirect (builder); \
         got sinks={:?}",
        result.sinks
    );
}

// ---------- W1-M5: NextJS + Fastify + NestJS sources ----------
//
// These seven tests exercise the source-side AST bank by demonstrating an
// end-to-end taint flow from a framework-shaped HTTP source to an `eval()`
// sink. Each test asserts:
//   * `result.sources` contains an entry of the expected `TaintSourceType`
//     (HttpBody / HttpParam) on the source line, AND
//   * `result.sinks` contains a `CodeEval` entry on the eval line, AND
//   * `result.flows` contains at least one flow connecting a source to a
//     sink — proving the source-side pattern flows through the full taint
//     pipeline.
//
// Pre-W1-M5: these tests pass via the regex bank's NEXTJS_PATTERNS /
// FASTIFY_PATTERNS / NESTJS_PATTERNS source patterns. Post-W1-M5 the same
// tests are also covered by the structural AST sources added to
// `TYPESCRIPT_AST_SOURCES`. Because Wave 1 is ADDITIVE (regex bank stays
// active), pre-add capture is expected to be GREEN — the milestone closes
// the parity gap so Wave 2's atomic deletion does not regress these flows.

/// Wave 1 source→eval flow assertion. Delegates to `common::
/// assert_source_to_eval_flow` so all integration tests share one
/// implementation; W1-M5's commit message documented this helper, and
/// W1.5-M6 promotes it to the shared module.
fn assert_source_to_eval_flow(result: &TaintInfo, expected_source: TaintSourceType) {
    common_assert_source_to_eval_flow(result, expected_source);
}

/// W1-M5 #1 — App Router `request.json()` (HttpBody) flowing into `eval`.
/// Pre-W1-M5: covered by NEXTJS_PATTERNS regex source
/// `request\.(json|text|formData)\s*\(`. Post-W1-M5: structural match via
/// `TYPESCRIPT_AST_SOURCES` member_pattern `('request', 'json')`.
#[test]
fn nextjs_request_json_to_eval_via_compute_taint() {
    let src = "\
export async function POST(request) {
    const data = await request.json();
    eval(data.code);
    return new Response(JSON.stringify({ok: true}));
}
";
    let result = analyze_with_ssa(src, Language::TypeScript, "POST", /* use_ssa */ false);
    assert_source_to_eval_flow(&result, TaintSourceType::HttpBody);
}

/// W1-M5 #2 — App Router `request.text()` (HttpBody) flowing into `eval`.
/// Post-W1-M5 covered by member_pattern `('request', 'text')`.
#[test]
fn nextjs_request_text_to_eval_via_compute_taint() {
    let src = "\
export async function POST(request) {
    const raw = await request.text();
    eval(raw);
}
";
    let result = analyze_with_ssa(src, Language::TypeScript, "POST", /* use_ssa */ false);
    assert_source_to_eval_flow(&result, TaintSourceType::HttpBody);
}

/// W1-M5 #3 — App Router `request.formData()` (HttpBody) flowing into
/// `eval`. Post-W1-M5 covered by member_pattern `('request', 'formData')`.
#[test]
fn nextjs_request_formdata_to_eval_via_compute_taint() {
    let src = "\
export async function POST(request) {
    const fd = await request.formData();
    eval(fd.get('script'));
}
";
    let result = analyze_with_ssa(src, Language::TypeScript, "POST", /* use_ssa */ false);
    assert_source_to_eval_flow(&result, TaintSourceType::HttpBody);
}

/// W1-M5 #4 — `request.nextUrl.searchParams.get('q')` (HttpParam) flowing
/// into `eval`. Post-W1-M5 covered by member_pattern
/// `('searchParams', 'get')` (structural) AND raw-fallback
/// `('', 'request.nextUrl.searchParams')`.
#[test]
fn nextjs_searchparams_get_to_eval_via_compute_taint() {
    let src = "\
export async function GET(request) {
    const q = request.nextUrl.searchParams.get('q');
    eval(q);
}
";
    let result = analyze_with_ssa(src, Language::TypeScript, "GET", /* use_ssa */ false);
    assert_source_to_eval_flow(&result, TaintSourceType::HttpParam);
}

/// W1-M5 #5 — Fastify handler `request.body` (HttpBody) flowing into
/// `eval`. Note the receiver is `request`, not `req`; the existing AST bank
/// only had `('req', 'body')`. Post-W1-M5 covered by `('request', 'body')`.
#[test]
fn fastify_request_body_to_eval_via_compute_taint() {
    let src = "\
import Fastify from 'fastify';
async function fastifyEcho(request, reply) {
    const cmd = request.body.cmd;
    eval(cmd);
}
";
    let result = analyze_with_ssa(
        src,
        Language::TypeScript,
        "fastifyEcho",
        /* use_ssa */ false,
    );
    assert_source_to_eval_flow(&result, TaintSourceType::HttpBody);
}

/// W1-M5 #6 — Fastify handler `request.query` (HttpParam) flowing into
/// `eval`. Pre-W1-M5: caught by FASTIFY_PATTERNS regex
/// `request\.(params|query|headers|cookies)\b`. Post-W1-M5: structural
/// match via member_pattern `('request', 'query')`.
#[test]
fn fastify_request_query_to_eval_via_compute_taint() {
    let src = "\
async function handler(request, reply) {
    const q = request.query.q;
    eval(q);
}
";
    let result = analyze_with_ssa(
        src,
        Language::TypeScript,
        "handler",
        /* use_ssa */ false,
    );
    assert_source_to_eval_flow(&result, TaintSourceType::HttpParam);
}

/// W1-M5 #7 — NestJS `@Req()`-style manual unwrap: `const body =
/// request.body; eval(body.script);`. The decorator is import-only context
/// (raw-fallback for the `@Body(`/`@Req(` decorators is wired in the AST
/// bank for v0.3.0+ structural lookups); this test exercises the manual
/// `request.body` access pattern that NestJS controllers also use after a
/// `@Req()` decorator unwraps the request. Post-W1-M5: covered by
/// member_pattern `('request', 'body')`.
#[test]
fn nestjs_request_body_to_eval_manual_unwrap_via_compute_taint() {
    let src = "\
import { Controller, Post, Req } from '@nestjs/common';
async function nestCreate(request) {
    const body = request.body;
    eval(body.script);
}
";
    let result = analyze_with_ssa(
        src,
        Language::TypeScript,
        "nestCreate",
        /* use_ssa */ false,
    );
    assert_source_to_eval_flow(&result, TaintSourceType::HttpBody);
}
