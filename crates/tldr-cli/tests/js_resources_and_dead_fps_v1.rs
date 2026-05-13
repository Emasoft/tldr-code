//! js-resources-and-dead-fps-v1 (v0.4.2 bug-F1 + bug-F2):
//!
//! Two correlated false-positive bug-classes in the TS/JS pipeline,
//! discovered by the Phase-20 audit follow-up worker pool (W-P) on the
//! canonical `/tmp/repos/express` material:
//!
//! ---------------------------------------------------------------------------
//! F1: `tldr resources` over-flags `var View = this.get('view');` as a
//!     `request`-type resource leak.
//! ---------------------------------------------------------------------------
//!
//! Real code from `/tmp/repos/express/lib/application.js:550`:
//!
//!   ```js
//!   var View = this.get('view');
//!
//!   view = new View(name, { ... });
//!   ```
//!
//! Pre-fix output (`tldr resources … render`):
//!
//!   ```json
//!   { "resources":[{"name":"View","resource_type":"request","line":550,"closed":false}],
//!     "leaks":    [{"resource":"View","line":550,"paths":null}] }
//!   ```
//!
//! Root cause: the TS/JS detector matches any RHS call ending in `.get`
//! against the creator alias `("get", "request")`. The AGG17-7 gate
//! (resources-ast-gate-v1) only narrowed *LHS* names — `event`, `request`,
//! `response`, `data`. A capitalised local like `View` slipped through.
//!
//! Fix: extend the AGG17-7 gate so that *ambiguous CREATOR aliases*
//! (`get`, `post`, `request`, `connect`, `getConnection`) also require
//! a confirming cleanup-method call on the LHS variable, regardless of
//! the variable's name. High-precision creators (`fetch`, `createServer`,
//! `createConnection`, `createReadStream`, `createWriteStream`, `open`,
//! `openSync`, `WebSocket`, `createPool`) remain unconditional.
//!
//! The audit copy described the FP as `new View()`. The real source on
//! application.js:550 is `var View = this.get('view');` — the `new View()`
//! at line 552 is unrelated (and never flagged by itself, since
//! `extract_call_name` on `new_expression` yields "new View", which is
//! NOT in the TS/JS creator alias list). Both the audit narrative and
//! the underlying behaviour collapse to the same fix.
//!
//! ---------------------------------------------------------------------------
//! F2: `tldr dead /tmp/repos/express` reports MIME-type keys from
//!     `res.format({'text/plain': function(){...}, ...})` as possibly_dead
//!     functions.
//! ---------------------------------------------------------------------------
//!
//! Pre-fix output (`tldr dead /tmp/repos/express`):
//!
//!   ```json
//!   { "possibly_dead": [
//!       {"name":"text/plain", "file":"test/res.format.js", ...},
//!       {"name":"text/html",  ...},
//!       {"name":"application/json", ...},
//!       {"name":"text/plain; charset=utf-8", ...},
//!       {"name":"text/html; foo=bar; bar=baz", ...},
//!       {"name":"application/json; q=0.5", ...}
//!   ] }
//!   ```
//!
//! Root cause: `extract_ts_pair_function` in
//! `crates/tldr-core/src/ast/extract.rs` accepts ANY `string`-kind key on
//! an object-literal `pair` whose value is a function. MIME-type strings
//! (`"text/plain"`, `"application/json; q=0.5"`) are passed to
//! `res.format({...})` as content-negotiation handlers, not as named
//! function definitions.
//!
//! Fix: when the pair key is a `string` (not a `property_identifier`),
//! validate that the unquoted content matches the JavaScript identifier
//! grammar `[A-Za-z_$][A-Za-z0-9_$]*`. Otherwise skip extraction.
//!
//! The narrower string-shape gate preserves the existing
//! `{ "foo": function() {} }` extraction (passes the regex) and the
//! `{ foo: function() {} }` shorthand (different key kind), while filtering
//! the MIME-type / header / URL-fragment cases that produced the FP class.
//!
//! ---------------------------------------------------------------------------
//! Real-repo gated per `no-synthetic-fixtures-v1`: every test below
//! returns early if `/tmp/repos/express` (or the relevant temp source) is
//! absent. Pre-fix repros are captured at
//! `/tmp/v042_pre_VAL-JS-PATTERNS_resources.json` and
//! `/tmp/v042_pre_VAL-JS-PATTERNS_dead.json`; post-fix repros at
//! `/tmp/v042_post_VAL-JS-PATTERNS_*.json`.

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

// ===========================================================================
// F1 #1 — Negative case: `var View = this.get('view')` in express render
//          MUST NOT be flagged as a resource.
// ===========================================================================

#[test]
fn js_resources_new_view_not_flagged() {
    let path = "/tmp/repos/express/lib/application.js";
    if !Path::new(path).exists() {
        return;
    }
    let (exit, out) = run_tldr(&["resources", path, "render", "--format", "json"]);
    // exit-code semantics: 0 = no resources/leaks, 3 = leaks detected.
    assert!(
        exit == 0 || exit == 3,
        "resources exit must be 0 or 3; got {}; out={}",
        exit,
        out
    );
    let v = parse_json(&out);
    let resources = v
        .get("resources")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    let names: Vec<String> = resources
        .iter()
        .filter_map(|r| {
            r.get("name")
                .and_then(|n| n.as_str())
                .map(|s| s.to_string())
        })
        .collect();
    assert!(
        !names.contains(&"View".to_string()),
        "F1: `var View = this.get('view')` MUST NOT be flagged as a resource — \
         `.get('view')` is a generic getter, not an HTTP get. names={:?}",
        names
    );
    let detected = v
        .pointer("/summary/resources_detected")
        .and_then(|x| x.as_u64())
        .unwrap_or(u64::MAX);
    assert_eq!(
        detected, 0,
        "F1: resources_detected must be 0 for express render; got {}; payload={}",
        detected, out
    );
}

// ===========================================================================
// F1 #2 — Positive case: the canonical Node.js `http.request(...).abort()`
//          idiom MUST continue to flag.
// ===========================================================================

#[test]
fn js_resources_real_http_request_still_flagged() {
    let dir = std::env::temp_dir().join("js_resources_fps_v1_http_req");
    std::fs::create_dir_all(&dir).expect("mkdir tempdir");
    let path = dir.join("http_req.js");
    // Variable is named `req` (NOT in TS_JS_AMBIGUOUS_NAMES — that's
    // `event/request/response/data`). The creator alias is `request`
    // (now in the new ambiguous-creator set), so the gate fires; but the
    // function body contains `req.abort()`, so the cleanup confirmation
    // re-enables the flagging.
    let src = r#"
const http = require("http");

function makeRequest() {
    const req = http.request({ host: "example.com", port: 80 });
    req.on("response", function (res) {
        res.resume();
    });
    req.abort();
}

module.exports = { makeRequest };
"#;
    std::fs::write(&path, src).expect("write tempfile");

    let (exit, out) = run_tldr(&[
        "resources",
        path.to_str().unwrap(),
        "makeRequest",
        "--format",
        "json",
    ]);
    assert!(
        exit == 0 || exit == 3,
        "resources exit must be 0 or 3; got {}; out={}",
        exit,
        out
    );
    let v = parse_json(&out);
    let resources = v
        .get("resources")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    let req_flagged = resources
        .iter()
        .any(|r| r.get("name").and_then(|n| n.as_str()) == Some("req"));
    assert!(
        req_flagged,
        "F1 positive: `const req = http.request(...)` followed by `req.abort()` \
         MUST still flag — the cleanup-method call confirms it's a real \
         resource. resources={:?}",
        resources
    );
}

// ===========================================================================
// F1 #3 — Non-regression: high-precision creator `createServer` continues
//          to flag (the gate only narrows ambiguous creators).
// ===========================================================================

#[test]
fn js_resources_high_precision_creator_still_flags() {
    let path = "/tmp/repos/express/lib/application.js";
    if !Path::new(path).exists() {
        return;
    }
    let (exit, out) = run_tldr(&["resources", path, "--format", "json"]);
    assert!(
        exit == 0 || exit == 3,
        "resources exit must be 0 or 3; got {}; out={}",
        exit,
        out
    );
    let v = parse_json(&out);
    let resources = v
        .get("resources")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    let names: Vec<String> = resources
        .iter()
        .filter_map(|r| {
            r.get("name")
                .and_then(|n| n.as_str())
                .map(|s| s.to_string())
        })
        .collect();
    // server-style names from createServer must continue to be detected
    // somewhere in the file (this asserts the gate didn't over-narrow).
    assert!(
        names.contains(&"server".to_string()),
        "F1 non-reg: high-precision `server = http.createServer(...)` must \
         continue to flag — gate only narrows ambiguous-creator aliases. \
         names={:?}",
        names
    );
}

// ===========================================================================
// F2 #1 — Negative case: MIME-type object-literal keys MUST NOT appear
//          in possibly_dead.
// ===========================================================================

#[test]
fn js_dead_excludes_object_literal_mime_keys() {
    let path = "/tmp/repos/express";
    if !Path::new(path).exists() {
        return;
    }
    let (exit, out) = run_tldr(&["dead", path, "--format", "json"]);
    // exit codes for dead: 0 (clean) / non-zero (findings); accept either.
    assert!(
        exit >= 0,
        "dead exit must be non-negative; got {}; out_head={:?}",
        exit,
        out.chars().take(200).collect::<String>()
    );
    let v = parse_json(&out);
    let possibly_dead = v
        .get("possibly_dead")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    let names: Vec<String> = possibly_dead
        .iter()
        .filter_map(|r| {
            r.get("name")
                .and_then(|n| n.as_str())
                .map(|s| s.to_string())
        })
        .collect();
    // The exact MIME-type keys flagged on express test/res.format.js
    let mime_keys = [
        "text/plain",
        "text/html",
        "application/json",
        "text/plain; charset=utf-8",
        "text/html; foo=bar; bar=baz",
        "application/json; q=0.5",
    ];
    for mk in mime_keys {
        assert!(
            !names.iter().any(|n| n == mk),
            "F2: MIME-type object-literal key {:?} MUST NOT be classified as a \
             dead function — it's a content-negotiation handler key for \
             res.format(). possibly_dead.names={:?}",
            mk,
            names
        );
    }
    // Additionally — no entry containing `/` should appear (broad invariant
    // covering any future MIME-type or path-shaped key).
    for n in &names {
        assert!(
            !n.contains('/'),
            "F2: possibly_dead entry {:?} contains '/' — string keys with \
             non-identifier characters must be skipped by the pair-extractor. \
             names={:?}",
            n,
            names
        );
    }
}

// ===========================================================================
// F2 #2 — Non-regression: a real-world unused exported function IS still
//          surfaced as possibly_dead.
//
//   The express checkout: `examples/search/public/client.js` has
//   `function search(query) {...}` which (in the express layout) is
//   referenced only by the page's <script> tag. The dead detector reports
//   it as possibly_dead with ref_count=0. We pin that here so the F2
//   filter doesn't accidentally swallow ALL string-keyed entries.
// ===========================================================================

#[test]
fn js_dead_still_detects_real_unused_function() {
    let path = "/tmp/repos/express";
    if !Path::new(path).exists() {
        return;
    }
    let (exit, out) = run_tldr(&["dead", path, "--format", "json"]);
    assert!(exit >= 0, "dead exit must be non-negative; got {}", exit);
    let v = parse_json(&out);
    let possibly_dead = v
        .get("possibly_dead")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    let count = possibly_dead.len();
    // After filtering 6 MIME keys we expect at least 1 surviving possibly_dead
    // entry (`onreadystatechange` from examples/search/public/client.js, or
    // `setHeaders` from test/express.static.js). The exact count is brittle
    // across tree-sitter grammar bumps, so we assert "at least one".
    assert!(
        count >= 1,
        "F2 non-reg: dead detector must still surface real unused functions \
         after the MIME-key filter. possibly_dead.len()={}; payload={}",
        count,
        out
    );
    // total_possibly_dead summary field must stay populated and non-zero.
    let total = v
        .pointer("/total_possibly_dead")
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    assert!(
        total >= 1,
        "F2 non-reg: total_possibly_dead must be >= 1 after the filter; \
         got {}; payload={}",
        total,
        out
    );
}

// ===========================================================================
// F2 #3 — Identifier-shaped string keys are STILL extracted.
//
//   `{ "foo": function() {} }` is the legitimate JSON-style object literal;
//   the `extract_ts_pair_function` accepts both bare-identifier and string
//   keys for the same semantic. We pin that the string-key path continues
//   to work for identifier-shaped strings (the gate only rejects strings
//   that don't match the JS identifier grammar).
// ===========================================================================

#[test]
fn js_pair_extractor_keeps_identifier_shaped_string_keys() {
    let dir = std::env::temp_dir().join("js_resources_fps_v1_string_id");
    std::fs::create_dir_all(&dir).expect("mkdir tempdir");
    let path = dir.join("string_id.js");
    let src = r#"
module.exports = {
  "foo": function() { return 1; },
  "barBaz": function(x) { return x; },
  "_private": (y) => y,
  "with/slash": function() { return "skip me"; },
  "text/plain": function() { return "skip me too"; }
};
"#;
    std::fs::write(&path, src).expect("write tempfile");

    let (exit, out) = run_tldr(&["extract", path.to_str().unwrap(), "--format", "json"]);
    assert!(
        exit == 0,
        "extract must succeed for valid JS; got exit={}; out={}",
        exit,
        out
    );
    let v = parse_json(&out);
    // ModuleInfo.functions[].name is what `dead` consumes.
    let functions = v
        .get("functions")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    let names: Vec<String> = functions
        .iter()
        .filter_map(|f| {
            f.get("name")
                .and_then(|n| n.as_str())
                .map(|s| s.to_string())
        })
        .collect();
    // Identifier-shaped string keys: must be present.
    for keep in ["foo", "barBaz", "_private"] {
        assert!(
            names.iter().any(|n| n == keep),
            "F2 keeps identifier-shaped string key {:?}: names={:?}",
            keep,
            names
        );
    }
    // Non-identifier-shaped string keys: must be filtered.
    for skip in ["with/slash", "text/plain"] {
        assert!(
            !names.iter().any(|n| n == skip),
            "F2 filters non-identifier-shaped string key {:?}: names={:?}",
            skip,
            names
        );
    }
}
