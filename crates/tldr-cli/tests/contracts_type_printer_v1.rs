//! contracts-type-printer-v1: CLUSTER-M-046 — preserve pointer indirection in
//! C type strings, ingest Elixir `@spec` and OCaml `.mli val` signatures,
//! recognize Swift `guard let` as a precondition, and exclude Scala
//! `implicit` parameters from precondition emission.
//!
//! Each test must FAIL on the parent commit and PASS post-fix. The tests
//! exercise the `tldr contracts` CLI end-to-end on small synthetic fixtures
//! (no external repos) so they remain hermetic and stable across CI runs.

use assert_cmd::Command;
use serde_json::Value;
use std::fs;
use tempfile::TempDir;

fn run_tldr(args: &[&str]) -> (i32, String, String) {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("tldr"));
    let output = cmd.args(args).output().expect("tldr binary missing");
    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (code, stdout, stderr)
}

/// Parse the JSON output of `tldr contracts` from stdout into a `Value`.
fn parse_contracts(stdout: &str) -> Value {
    serde_json::from_str(stdout).unwrap_or_else(|e| {
        panic!(
            "expected JSON contracts output but got parse error: {e}\nstdout was:\n{stdout}"
        )
    })
}

// =============================================================================
// C — pointer indirection preserved in type string
// =============================================================================
//
// Pre-fix: `const char *init` parameter renders as `init: char` (loses both
// `const` qualifier and `*` pointer indirection).
// Post-fix: `init: const char *` (or `init: char *`) — the trailing `*` MUST
// be preserved so the type string distinguishes a `char` from a `char *`.

#[test]
fn test_c_pointer_param_preserves_pointer_indirection() {
    let dir = TempDir::new().unwrap();
    let src = "\
typedef char *sds;

sds sdsnew(const char *init) {
    return 0;
}
";
    let path = dir.path().join("sds.c");
    fs::write(&path, src).unwrap();

    let (code, stdout, stderr) =
        run_tldr(&["contracts", path.to_str().unwrap(), "sdsnew", "--format", "json"]);
    assert_eq!(code, 0, "contracts failed: stderr={stderr}\nstdout={stdout}");

    let report = parse_contracts(&stdout);
    let pre = report["preconditions"].as_array().expect("preconditions array");
    let init_cond = pre
        .iter()
        .find(|c| c["variable"] == "init")
        .unwrap_or_else(|| panic!("no 'init' precondition; got {pre:?}"));
    let constraint = init_cond["constraint"].as_str().unwrap();
    assert!(
        constraint.contains('*'),
        "expected pointer indirection '*' in C type-string constraint, got: {constraint}"
    );
    // Also confirm `char` is still present (no regression on the base type).
    assert!(
        constraint.contains("char"),
        "expected 'char' in C type-string constraint, got: {constraint}"
    );
}

// =============================================================================
// Elixir — @spec ingested as a typed precondition
// =============================================================================
//
// Pre-fix: `def send_resp(conn)` with an adjacent `@spec send_resp(t) :: t`
// emits 0 preconditions / 0 postconditions. Post-fix: the @spec is consumed —
// `conn` gets a precondition tagged with `: t` and the return gets `t`.

#[test]
fn test_elixir_spec_ingested_as_contract() {
    let dir = TempDir::new().unwrap();
    let src = r#"defmodule Conn do
  @type t :: %__MODULE__{state: atom}

  @spec send_resp(t) :: t
  def send_resp(conn) do
    conn
  end
end
"#;
    let path = dir.path().join("conn.ex");
    fs::write(&path, src).unwrap();

    let (code, stdout, stderr) = run_tldr(&[
        "contracts",
        path.to_str().unwrap(),
        "send_resp",
        "--format",
        "json",
    ]);
    assert_eq!(code, 0, "contracts failed: stderr={stderr}\nstdout={stdout}");

    let report = parse_contracts(&stdout);
    let pre = report["preconditions"].as_array().expect("preconditions");
    let post = report["postconditions"].as_array().expect("postconditions");

    // A precondition derived from the @spec must mention the typed name `t`.
    let has_typed_pre = pre.iter().any(|c| {
        c["constraint"].as_str().is_some_and(|s| s.contains(": t"))
            || c["constraint"].as_str().is_some_and(|s| s == "t")
    });
    assert!(
        has_typed_pre,
        "expected @spec-derived typed precondition referencing 't'; got {pre:?}"
    );

    // The return-type from the @spec must appear as a postcondition.
    let has_typed_post = post.iter().any(|c| {
        c["variable"] == "return"
            && c["constraint"].as_str().is_some_and(|s| s.contains('t'))
    });
    assert!(
        has_typed_post,
        "expected @spec-derived return postcondition referencing 't'; got {post:?}"
    );
}

// =============================================================================
// OCaml — .mli val signatures ingested as preconditions/postconditions
// =============================================================================
//
// Pre-fix: `tldr contracts foo.mli some_val` returns empty pre/post even when
// the `.mli` defines `val some_val : int -> string`.
// Post-fix: the val signature is parsed; parameters and return type are
// surfaced as low-confidence pre/postconditions.

#[test]
fn test_ocaml_mli_val_signature_ingested() {
    let dir = TempDir::new().unwrap();
    let src = "\
val make : int -> string -> (int * string)
";
    let path = dir.path().join("metrics.mli");
    fs::write(&path, src).unwrap();

    let (code, stdout, stderr) = run_tldr(&[
        "contracts",
        path.to_str().unwrap(),
        "make",
        "--format",
        "json",
    ]);
    assert_eq!(code, 0, "contracts failed: stderr={stderr}\nstdout={stdout}");

    let report = parse_contracts(&stdout);
    let pre = report["preconditions"].as_array().expect("preconditions");
    let post = report["postconditions"].as_array().expect("postconditions");

    // The val signature has at least 2 arrow-separated arg types.
    // Either count parameter pres OR ensure the return postcondition holds
    // the arrow tail.
    assert!(
        !pre.is_empty(),
        "expected at least one precondition from .mli val signature; got {pre:?}"
    );
    let has_return_post = post.iter().any(|c| c["variable"] == "return");
    assert!(
        has_return_post,
        "expected a return postcondition derived from .mli val signature; got {post:?}"
    );
}

// =============================================================================
// Swift — `guard let X = Y else { return }` becomes a non-nil precondition
// =============================================================================
//
// Pre-fix: Swift `guard let bucket = self._find(key).bucket else { return nil }`
// produces no precondition for `bucket`.
// Post-fix: `bucket` carries a `bucket != nil` (or `nonnil(bucket)`)
// precondition — after the guard, `bucket` is guaranteed non-nil.

#[test]
fn test_swift_guard_let_recognized_as_precondition() {
    let dir = TempDir::new().unwrap();
    let src = "\
func lookup(key: String) -> String? {
    guard let bucket = find(key) else { return nil }
    return bucket
}
";
    let path = dir.path().join("Lookup.swift");
    fs::write(&path, src).unwrap();

    let (code, stdout, stderr) = run_tldr(&[
        "contracts",
        path.to_str().unwrap(),
        "lookup",
        "--format",
        "json",
    ]);
    assert_eq!(code, 0, "contracts failed: stderr={stderr}\nstdout={stdout}");

    let report = parse_contracts(&stdout);
    let pre = report["preconditions"].as_array().expect("preconditions");
    let has_bucket_nonnil = pre.iter().any(|c| {
        c["variable"] == "bucket"
            && c["constraint"]
                .as_str()
                .is_some_and(|s| s.contains("!= nil") || s.contains("nonnil") || s.contains("non-nil"))
    });
    assert!(
        has_bucket_nonnil,
        "expected `bucket != nil` (or nonnil) precondition from guard-let; got {pre:?}"
    );
}

// =============================================================================
// Scala — `implicit` parameters NOT flagged as preconditions on the function
// =============================================================================
//
// Pre-fix: `def interpret[B](a: A)(implicit G: Async[G], B: Monoid[B])`
// produces `parameter G is required` and `parameter B is required` — the
// implicit type-class evidences are surfaced as caller-required arguments,
// which is wrong: they are resolved by the compiler, not passed at the call
// site.
// Post-fix: implicit params are excluded; only the non-implicit `a`
// produces a precondition (if any), and `G` / `B` do NOT appear.

#[test]
fn test_scala_implicit_param_not_a_precondition() {
    let dir = TempDir::new().unwrap();
    // Use distinct names for the type parameter (`X`) and the implicit
    // evidence params (`evG`, `evM`) so a precondition variable can only
    // come from one source.
    let src = "\
def interpret[X](a: Int)(implicit evG: Monoid[Int], evM: Monoid[X]): X = ???
";
    let path = dir.path().join("Interpret.scala");
    fs::write(&path, src).unwrap();

    let (code, stdout, stderr) = run_tldr(&[
        "contracts",
        path.to_str().unwrap(),
        "interpret",
        "--format",
        "json",
    ]);
    assert_eq!(code, 0, "contracts failed: stderr={stderr}\nstdout={stdout}");

    let report = parse_contracts(&stdout);
    let pre = report["preconditions"].as_array().expect("preconditions");
    let has_implicit_g = pre.iter().any(|c| c["variable"] == "evG");
    let has_implicit_m = pre.iter().any(|c| c["variable"] == "evM");
    assert!(
        !has_implicit_g,
        "implicit type-class param `evG` must NOT be a precondition; got {pre:?}"
    );
    assert!(
        !has_implicit_m,
        "implicit type-class param `evM` must NOT be a precondition; got {pre:?}"
    );
}
