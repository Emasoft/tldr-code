//! vuln-secure-autodetect-parity-v1 (M-AA5) — RED guard for the
//! autodetect-path discrepancy between `tldr vuln` and `tldr secure`.
//!
//! Pre-fix repro on `/tmp/repos/express` (a JS-only tree, no `--lang`):
//!
//! ```text
//!   tldr vuln /tmp/repos/express   | jq '.findings | length'        => 1
//!   tldr secure /tmp/repos/express | jq '.summary.taint_count'      => 0
//! ```
//!
//! The discrepancy traced to secure's `collect_files` lacking the
//! autodetect step: with `lang = None`, `is_supported_secure_file`
//! matches only `py | rs`, so a JS-only tree silently produced an
//! empty file set.
//!
//! M-Z10 (`secure-test-file-suppression-v1`) made vuln+secure agree
//! when `--lang` is EXPLICIT (test-file suppression parity). M-AA5
//! closes the symmetric autodetect-path gap by mirroring vuln's
//! language-resolution prelude in secure.
//!
//! Validation: build a synthetic JS-only directory with a real
//! source-to-sink command-injection flow, run both `tldr vuln <dir>`
//! and `tldr secure <dir>` (NO `--lang`), and assert
//! `vuln.findings.length == secure.summary.taint_count`.

use assert_cmd::Command;
use serde_json::Value;
use tempfile::TempDir;

fn run_tldr_capture(args: &[&str]) -> (i32, String) {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("tldr"));
    let output = cmd.args(args).output().expect("tldr binary missing");
    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    (code, stdout)
}

/// Build a JS-only synthetic directory with a `package.json` (so the
/// manifest-priority detector picks JavaScript) and an `index.js`
/// containing a real source-to-sink command-injection flow.
fn make_synthetic_js_dir() -> TempDir {
    let dir = TempDir::new().expect("create tempdir");
    // package.json => manifest-priority makes Language::from_directory
    // return Some(JavaScript) deterministically (M-AA1 ordering).
    std::fs::write(
        dir.path().join("package.json"),
        r#"{"name":"vuln-secure-parity-fixture","version":"0.0.1"}"#,
    )
    .expect("write package.json");
    // index.js: req.params.user_id (taint source: Express route param)
    // → res.redirect(...) (sink: PathTraversal). This mirrors the
    // express examples/mvc/controllers/user-pet/index.js flow that
    // produces 1 finding in the real express repo. The exact function
    // shape (`exports.create = function(req, res, next){ ... }`) is
    // load-bearing — the taint engine's intra-procedural pass walks
    // function bodies, so the source/sink must live in the same
    // function definition the parser sees as a single scope.
    std::fs::write(
        dir.path().join("index.js"),
        r#"'use strict'

exports.name = 'pet';
exports.prefix = '/user/:user_id';

exports.create = function(req, res, next){
  var id = req.params.user_id;
  res.redirect('/user/' + id);
};
"#,
    )
    .expect("write index.js");
    dir
}

/// vuln-secure-autodetect-parity-v1: synthetic-dir parity guard.
/// `tldr vuln <dir>` and `tldr secure <dir>` (no `--lang`) MUST agree
/// on the count of taint-class findings.
#[test]
fn test_vuln_secure_autodetect_parity_express() {
    let dir = make_synthetic_js_dir();
    let path = dir.path().to_str().expect("utf8 tempdir");

    // tldr vuln <dir> (no --lang) — exit 2 means findings detected, exit
    // 0 means no findings; both are valid for parity. Exit 1 is an
    // analysis failure and would fail the test.
    let (vuln_code, vuln_stdout) = run_tldr_capture(&["vuln", path]);
    assert!(
        vuln_code == 0 || vuln_code == 2,
        "tldr vuln autodetect failed (exit {vuln_code}); stdout:\n{vuln_stdout}"
    );
    let vuln_json: Value = serde_json::from_str(&vuln_stdout).expect("vuln stdout must be JSON");
    let vuln_findings = vuln_json
        .get("findings")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);

    // tldr secure <dir> (no --lang) — exit 0 expected (secure has no
    // findings-detected exit-code policy).
    let (secure_code, secure_stdout) = run_tldr_capture(&["secure", path]);
    assert_eq!(
        secure_code, 0,
        "tldr secure autodetect failed (exit {secure_code}); stdout:\n{secure_stdout}"
    );
    let secure_json: Value =
        serde_json::from_str(&secure_stdout).expect("secure stdout must be JSON");
    let secure_taint_count = secure_json
        .pointer("/summary/taint_count")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;

    // The fixture must produce at least one finding for the parity
    // assertion to be meaningful — if both are 0 the test silently
    // passes on a broken pipeline. Pin a >=1 lower bound on vuln so
    // the parity check actually exercises the autodetect path.
    assert!(
        vuln_findings >= 1,
        "fixture produced 0 vuln findings — autodetect path is broken or fixture is wrong; \
         vuln stdout:\n{vuln_stdout}"
    );

    assert_eq!(
        vuln_findings, secure_taint_count,
        "vuln↔secure autodetect parity broken: vuln.findings.length={vuln_findings}, \
         secure.summary.taint_count={secure_taint_count}. Both should agree on the \
         autodetect path (no --lang); M-AA5 fix should keep them in lock-step.\n\
         vuln stdout:\n{vuln_stdout}\n\
         secure stdout:\n{secure_stdout}"
    );
}
