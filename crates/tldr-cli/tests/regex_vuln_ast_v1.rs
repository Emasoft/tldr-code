//! regex-vuln-ast-v1 — AST-rewrite of two name-/substring-heuristic vuln sinks.
//!
//! Cluster REGEX-VULN (v0.5.0). Two over-matching sink heuristics in
//! `crates/tldr-core/src/security/taint.rs` flag findings on the *name* or a
//! *substring*, not the actual AST call site:
//!
//! BUG 1 — TypeScript SQL sink fires on ANY `.query` (property name).
//!   The TS sink bank entry `member_patterns: &[("*", "query"), ("*", "execute")]`
//!   (TaintSinkType::SqlQuery) matches every `member_expression` whose property
//!   is literally `query` / `execute` — even a plain property *read* that is
//!   NOT a call. So an object/config that merely exposes a `.query` field, or a
//!   `.query` value passed as an argument, is mislabelled a SQL-injection sink.
//!   A real DB call `db.query(userInput)` must STILL fire.
//!
//! BUG 2 — PHP SSRF/HttpRequest sink over-matches via raw `->request(` /
//!   `Guzzle\Client` substring entries. The raw-substring fallback fires on any
//!   node whose text *contains* the substring — including string concatenation
//!   and output operations that are not real HTTP-client call sites. A real
//!   `curl_exec(...)` / `file_get_contents($url)` on tainted input must STILL
//!   fire.
//!
//! FIX SHAPE (AST-driven, no regex): the TS `.query`/`.execute` SqlQuery sink
//! must require an actual `call_expression` whose callee is the `.query(...)`
//! member-access — a property read alone is not a sink. The PHP SSRF sink must
//! require a real call site of the actual sink function (member_call_expression
//! callee identity for `->request`, function_call for curl/file_get_contents),
//! not a string/output op that merely contains the substring.
//!
//! Validation (all through the real `tldr vuln` CLI):
//!   TS  negative — object literal + property read of `.query` ⇒ ZERO sql_injection.
//!   TS  positive — `db.query(userInput)` real DB call ⇒ ≥1 sql_injection.
//!   PHP negative — string concat / echo with `->request` text ⇒ ZERO ssrf.
//!   PHP positive — `curl_exec` / `file_get_contents($tainted)` ⇒ ≥1 ssrf.

use assert_cmd::Command;
use serde_json::Value;
use std::io::Write;
use tempfile::TempDir;

/// Write `src` into `<tmp>/<name>` and return the temp dir (kept alive) plus
/// the file path.
fn write_fixture(name: &str, src: &str) -> (TempDir, std::path::PathBuf) {
    let dir = TempDir::new().expect("create tempdir");
    let path = dir.path().join(name);
    let mut f = std::fs::File::create(&path).expect("create fixture file");
    f.write_all(src.as_bytes()).expect("write fixture");
    f.flush().expect("flush fixture");
    (dir, path)
}

/// Run `tldr vuln <file> --lang <lang> --format json --quiet` and parse JSON.
/// The vuln command exits non-zero when findings are present, so we use
/// `output()` not `success()`.
fn run_vuln_json(path: &std::path::Path, lang: &str) -> Value {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("tldr"));
    cmd.arg("vuln")
        .arg(path)
        .arg("--lang")
        .arg(lang)
        .arg("--format")
        .arg("json")
        .arg("--quiet");

    let output = cmd.output().expect("failed to execute tldr vuln");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "failed to parse `tldr vuln --lang {} --format json` JSON: {}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            lang,
            e,
            stdout,
            String::from_utf8_lossy(&output.stderr),
        )
    })
}

fn count_findings_of_type(report: &Value, vt_wire: &str) -> usize {
    report
        .get("findings")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter(|f| {
                    f.get("vuln_type")
                        .and_then(|v| v.as_str())
                        .map(|s| s == vt_wire)
                        .unwrap_or(false)
                })
                .count()
        })
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// BUG 1 — TypeScript `.query` SQL sink: name-heuristic ⇒ AST call site.
// ---------------------------------------------------------------------------

/// NEGATIVE: a `.query` that is a plain *property* — an object literal key and
/// a property *read* passed as an argument — is NOT a SQL-execution call site,
/// so it must emit ZERO sql_injection findings. On unfixed HEAD the
/// `("*", "query")` member-access heuristic fires on the property read.
#[test]
fn ts_property_query_emits_no_sql_injection() {
    let src = r#"
function handler(req: any, res: any) {
    const userInput = req.query.id;
    // `.query` here is a non-DB property: an object literal field and a
    // property read passed as a logger argument. Neither is a call site.
    const config = {
        query: userInput,
        execute: false,
    };
    logger.info(config.query);
    sendTo(req.query);
    return config;
}
"#;
    let (_dir, path) = write_fixture("ts_property_query_fp.ts", src);
    let report = run_vuln_json(&path, "typescript");
    let count = count_findings_of_type(&report, "sql_injection");
    assert_eq!(
        count, 0,
        "a non-DB `.query` property (object literal key / property read) MUST NOT \
         emit a sql_injection finding; the TS SqlQuery sink must require a real \
         `.query(...)` call_expression, not a property-name match. got {} in:\n{}",
        count,
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

/// POSITIVE: a real `db.query(userInput)` DB call on tainted input MUST emit a
/// sql_injection finding — verifies the AST rewrite did not gut real detection.
#[test]
fn ts_real_db_query_call_emits_sql_injection() {
    let src = r#"
function handler(req: any, res: any) {
    const userInput = req.query.id;
    const sql = "SELECT * FROM users WHERE id = " + userInput;
    db.query(sql);
}
"#;
    let (_dir, path) = write_fixture("ts_real_db_query.ts", src);
    let report = run_vuln_json(&path, "typescript");
    let count = count_findings_of_type(&report, "sql_injection");
    assert!(
        count >= 1,
        "a real `db.query(<tainted>)` call MUST emit ≥1 sql_injection finding; \
         got {} in:\n{}",
        count,
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

// ---------------------------------------------------------------------------
// BUG 2 — PHP SSRF/HttpRequest sink: substring-heuristic ⇒ AST call site.
// ---------------------------------------------------------------------------

/// NEGATIVE (Guzzle instantiation): `new \Guzzle\Client($url)` is a class
/// *instantiation* — it performs NO network I/O, so it is not an HTTP-request
/// sink. On unfixed HEAD the bogus `("", "Guzzle\\Client")` raw-substring entry
/// fires SSRF on the instantiation. The SSRF sink must require a real
/// HTTP-request call site, not a class name appearing in the source text.
#[test]
fn php_guzzle_instantiation_emits_no_ssrf() {
    let src = r#"<?php
function make($_GET) {
    $url = $_GET['url'];
    // Instantiating a client object does no network I/O — not an SSRF sink.
    $client = new \Guzzle\Client($url);
    return $client;
}
"#;
    let (_dir, path) = write_fixture("php_guzzle_instantiation_fp.php", src);
    let report = run_vuln_json(&path, "php");
    let count = count_findings_of_type(&report, "ssrf");
    assert_eq!(
        count, 0,
        "`new \\Guzzle\\Client($url)` is a class instantiation (no network I/O); \
         it MUST NOT emit an ssrf finding. The SSRF sink must require a real \
         HTTP-request call site, not a class-name substring. got {} in:\n{}",
        count,
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

/// NEGATIVE (string concat): a plain string built via concatenation that merely
/// *contains* the `->request(` text is a string/output op, not a real call site,
/// so it MUST emit ZERO ssrf findings. (Spec-mandated negative.)
#[test]
fn php_string_concat_request_emits_no_ssrf() {
    let src = r#"<?php
function build($_GET) {
    $url = $_GET['url'];
    // A plain string that textually contains the `->request(` substring but is
    // NOT a call: it is just a log message built via string concatenation.
    $msg = "client" . "->request(" . $url . ") was prepared";
    echo $msg;
    return $msg;
}
"#;
    let (_dir, path) = write_fixture("php_string_concat_fp.php", src);
    let report = run_vuln_json(&path, "php");
    let count = count_findings_of_type(&report, "ssrf");
    assert_eq!(
        count, 0,
        "PHP string concat that only CONTAINS the `->request(` substring (a \
         string/output op, not a real HTTP-client call) MUST NOT emit an ssrf \
         finding; the SSRF sink must require a real call site. got {} in:\n{}",
        count,
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

/// POSITIVE: a real `curl_exec` / `file_get_contents($tainted)` call on tainted
/// input MUST emit an ssrf finding — verifies the AST rewrite did not gut real
/// SSRF detection.
#[test]
fn php_real_curl_exec_emits_ssrf() {
    let src = r#"<?php
function fetch($_GET) {
    $url = $_GET['url'];
    $data = file_get_contents($url);
    return $data;
}
"#;
    let (_dir, path) = write_fixture("php_real_curl.php", src);
    let report = run_vuln_json(&path, "php");
    let count = count_findings_of_type(&report, "ssrf");
    assert!(
        count >= 1,
        "a real `file_get_contents(<tainted>)` HTTP-capable call MUST emit ≥1 \
         ssrf finding; got {} in:\n{}",
        count,
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

/// POSITIVE (Guzzle): a real `$client->request('GET', $url)` HTTP-client method
/// call on tainted input MUST still emit an ssrf finding — verifies the
/// structural call-site match preserved the legitimate `->request` SSRF sink.
#[test]
fn php_real_guzzle_request_emits_ssrf() {
    let src = r#"<?php
function fetch($_GET, $client) {
    $url = $_GET['url'];
    $resp = $client->request('GET', $url);
    return $resp;
}
"#;
    let (_dir, path) = write_fixture("php_real_guzzle_request.php", src);
    let report = run_vuln_json(&path, "php");
    let count = count_findings_of_type(&report, "ssrf");
    assert!(
        count >= 1,
        "a real `$client->request('GET', <tainted>)` HTTP-client call MUST emit \
         ≥1 ssrf finding; got {} in:\n{}",
        count,
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}
