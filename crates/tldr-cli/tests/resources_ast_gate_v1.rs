//! resources-ast-gate-v1 (P17.AGG17-7): Option-B AST gate for the TS/JS
//! `tldr resources` heuristic.
//!
//! The phase-17 final-review aggregate flagged AGG17-7 as judgment-call:
//! `tldr resources` over-flagged TS/JS variables named `event`, `request`,
//! `response`, `data` when they were Map lookups, function parameters, or
//! plain object shapes — not real resource handles. The current detector
//! treats any RHS call ending in `.get` / `.post` / `connect` / `request`
//! as a resource creator, which combined with the generic LHS variable
//! name yields a high false-positive rate.
//!
//! Fix (Option B — AST gate, pre-/post-fix verified on the canonical
//! `/tmp/repos/ts-dom-gen` material):
//!
//!   For TypeScript / JavaScript only, when the LHS variable name is in
//!   the *ambiguous set* `{event, request, response, data}`, the resource
//!   is registered ONLY IF some `<var_name>.<cleanup>(…)` call appears
//!   anywhere in the same function body, where `<cleanup>` is one of
//!   `close`, `destroy`, `end`, `abort`, `disconnect`, `release`,
//!   `unref`, `removeListener`, `removeAllListeners`,
//!   `removeEventListener`, `unsubscribe`, `cancel`. High-precision names
//!   (`file`, `conn`, `socket`, `stream`, `server`, `db`, …) are NOT
//!   subject to this gate — their name alone is a strong enough hint.
//!
//! Pre-fix evidence (HEAD f53dda9, before the gate):
//!
//!   ```text
//!   $ tldr resources /tmp/repos/ts-dom-gen/src/build/emitter.ts emitWebIdl
//!   {
//!     "resources": [{ "name": "event", "resource_type": "request",
//!                     "line": 363, "closed": false }],
//!     "leaks":     [{ "resource": "event", "line": 363, "paths": null }]
//!   }
//!   ```
//!
//!   The flagged `event` is `const event = webidl.events?.get(i.name)?.get(eName);`
//!   (a chained Map lookup) — definitively NOT a resource handle.
//!
//! Post-fix expectation: `resources_detected = 0` for the same call.
//!
//! Per `no-synthetic-fixtures-v1`: the negative case gates on
//! `/tmp/repos/ts-dom-gen` real-repo material. The positive case uses a
//! tempfile written from a real-world Node.js EventEmitter idiom (the
//! library doesn't ship as part of `/tmp/repos`, but the pattern is the
//! canonical `request.abort()` / `event.removeListener()` cleanup found
//! verbatim in the Node.js docs and the `events`/`http` stdlib).

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
// 1. Negative case (the actual bug): real ts-dom-gen `event` Map-lookup is
//    NOT flagged after the gate.
// ===========================================================================

#[test]
fn agg17_7_ts_dom_gen_event_map_lookup_not_flagged() {
    let path = "/tmp/repos/ts-dom-gen/src/build/emitter.ts";
    if !Path::new(path).exists() {
        return;
    }
    let (exit, out) = run_tldr(&["resources", path, "emitWebIdl", "--format", "json"]);
    // exit-code semantics: 0 = no resources/leaks, 3 = leaks detected.
    // Both are valid; we assert on payload, not exit.
    assert!(
        exit == 0 || exit == 3,
        "resources exit must be 0 (no leaks) or 3 (leaks detected); got {}; out={}",
        exit,
        out
    );
    let v = parse_json(&out);
    let detected = v
        .pointer("/summary/resources_detected")
        .and_then(|x| x.as_u64())
        .unwrap_or(u64::MAX);
    assert_eq!(
        detected, 0,
        "AGG17-7: ambiguous-name `event` from `webidl.events?.get(...)?.get(...)` \
         must NOT be flagged after the AST gate; got summary={}, payload={}",
        detected, out
    );
    let resources = v.get("resources").and_then(|x| x.as_array()).cloned();
    let names: Vec<String> = resources
        .unwrap_or_default()
        .into_iter()
        .filter_map(|r| {
            r.get("name")
                .and_then(|n| n.as_str())
                .map(|s| s.to_string())
        })
        .collect();
    assert!(
        !names.contains(&"event".to_string()),
        "resources[].name must not contain `event` for emitWebIdl: got names={:?}",
        names
    );
}

// ===========================================================================
// 2. Positive case (real-world Node.js cleanup idiom): an ambiguous name
//    that DOES carry a cleanup-method call is still flagged.
//
//    Pattern: `const request = http.request(opts); ...; request.abort();`
//    is verbatim from the Node.js `http` documentation and is the canonical
//    way to manage an outgoing HTTP request lifecycle.
// ===========================================================================

#[test]
fn agg17_7_positive_ambiguous_name_with_cleanup_still_flags() {
    let dir = std::env::temp_dir().join("agg17_7_resources_ast_gate");
    std::fs::create_dir_all(&dir).expect("mkdir tempdir");
    let path = dir.join("positive.ts");
    let src = r#"
import * as http from "http";

export function makeRequest(): void {
    const request = http.request({ host: "example.com", port: 80 });
    request.on("response", (res) => {
        res.resume();
    });
    request.abort();
}
"#;
    std::fs::write(&path, src).expect("write tempfile");

    let (exit, out) = run_tldr(&[
        "resources",
        path.to_str().unwrap(),
        "makeRequest",
        "--format",
        "json",
    ]);
    // exit-code semantics: 0 = no resources/leaks, 3 = leaks detected.
    // Both are valid; we assert on payload, not exit.
    assert!(
        exit == 0 || exit == 3,
        "resources exit must be 0 (no leaks) or 3 (leaks detected); got {}; out={}",
        exit,
        out
    );
    let v = parse_json(&out);
    let resources = v
        .get("resources")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    let request_flagged = resources
        .iter()
        .any(|r| r.get("name").and_then(|n| n.as_str()) == Some("request"));
    assert!(
        request_flagged,
        "AGG17-7 positive: `const request = http.request(...)` followed by \
         `request.abort()` MUST still flag — the cleanup-method call confirms \
         it's a real resource. resources={:?}",
        resources
    );
}

// ===========================================================================
// 3. Non-regression — high-precision names are NOT subject to the gate.
//    A `var server = http.createServer(...)` in real express must continue
//    to be flagged exactly as before.
// ===========================================================================

#[test]
fn agg17_7_non_regression_express_server_still_flags() {
    let path = "/tmp/repos/express/lib/application.js";
    if !Path::new(path).exists() {
        return;
    }
    let (exit, out) = run_tldr(&["resources", path, "--format", "json"]);
    // exit-code semantics: 0 = no resources/leaks, 3 = leaks detected.
    // Both are valid; we assert on payload, not exit.
    assert!(
        exit == 0 || exit == 3,
        "resources exit must be 0 (no leaks) or 3 (leaks detected); got {}; out={}",
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
        names.contains(&"server".to_string()),
        "high-precision name `server` (= http.createServer(...)) must continue \
         to be flagged after the AGG17-7 gate (the gate only narrows ambiguous \
         names): got names={:?}",
        names
    );
}

// ===========================================================================
// 4. Non-regression — high-precision name on Python (open(...) → file).
//    The TS/JS gate must not affect Python's `f = open(path)` pattern.
// ===========================================================================

#[test]
fn agg17_7_non_regression_python_open_still_flags() {
    let dir = std::env::temp_dir().join("agg17_7_resources_python");
    std::fs::create_dir_all(&dir).expect("mkdir tempdir");
    let path = dir.join("py_open.py");
    let src = r#"
def read_first_line(path):
    f = open(path, "r")
    line = f.readline()
    return line
"#;
    std::fs::write(&path, src).expect("write tempfile");

    let (exit, out) = run_tldr(&[
        "resources",
        path.to_str().unwrap(),
        "read_first_line",
        "--format",
        "json",
    ]);
    // exit-code semantics: 0 = no resources/leaks, 3 = leaks detected.
    // Both are valid; we assert on payload, not exit.
    assert!(
        exit == 0 || exit == 3,
        "resources exit must be 0 (no leaks) or 3 (leaks detected); got {}; out={}",
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
        names.contains(&"f".to_string()),
        "Python `f = open(...)` must continue to flag `f` as a file resource — \
         the AGG17-7 gate is TS/JS-only: got names={:?}",
        names
    );
}

// ===========================================================================
// 5. Boundary — a TS variable named `data` from a fetch call WITHOUT cleanup
//    is NOT flagged (matches the bug-class the fix is meant to address).
// ===========================================================================

#[test]
fn agg17_7_ts_data_without_cleanup_not_flagged() {
    let dir = std::env::temp_dir().join("agg17_7_resources_data");
    std::fs::create_dir_all(&dir).expect("mkdir tempdir");
    let path = dir.join("data_no_cleanup.ts");
    // `const data = config.get("key")` — `data` is in the ambiguous set,
    // RHS ends in `.get` (a TS/JS creator alias), no cleanup methods are
    // ever called on `data`. The pre-fix detector flagged this; the
    // post-fix gate must skip it.
    let src = r#"
type Config = { get(key: string): string };

export function readConfig(config: Config): string {
    const data = config.get("api_key");
    return data;
}
"#;
    std::fs::write(&path, src).expect("write tempfile");

    let (exit, out) = run_tldr(&[
        "resources",
        path.to_str().unwrap(),
        "readConfig",
        "--format",
        "json",
    ]);
    // exit-code semantics: 0 = no resources/leaks, 3 = leaks detected.
    // Both are valid; we assert on payload, not exit.
    assert!(
        exit == 0 || exit == 3,
        "resources exit must be 0 (no leaks) or 3 (leaks detected); got {}; out={}",
        exit,
        out
    );
    let v = parse_json(&out);
    let detected = v
        .pointer("/summary/resources_detected")
        .and_then(|x| x.as_u64())
        .unwrap_or(u64::MAX);
    assert_eq!(
        detected, 0,
        "ambiguous `data` from `.get(...)` without cleanup MUST be skipped: \
         got detected={}, payload={}",
        detected, out
    );
}
