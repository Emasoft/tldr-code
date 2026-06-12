//! M15 — flat per-function tainted-vars list alongside the block-keyed map.
//!
//! `TaintInfo.tainted_vars` is `HashMap<usize, HashSet<String>>` keyed by CFG
//! block id. Consumers (bugbot L2, vuln/secure surfaces) want a flat
//! per-function view too. M15 adds an ADDITIVE `tainted_vars_flat: Vec<String>`
//! field = the deterministic, deduplicated, SSA-suffix-stripped union of every
//! block's tainted variable set, sorted lexicographically.
//!
//! These tests drive the new field from the `tldr taint -f json` surface on a
//! REAL corpus function (the Flask tutorial `register` view in
//! `/tmp/tldr_corpora/python-flask`), which threads `request.form["username"]`
//! / `request.form["password"]` (HttpParam sources) into a `db.execute(...)`
//! SQL sink. The block-keyed `tainted_vars` map for that function holds
//! `{error, password, username}`, so the flat list MUST equal that sorted
//! union with no duplicates and no `_<n>` SSA version suffixes.

use std::path::Path;
use std::process::Command;

use serde_json::Value;

/// Absolute path to the release binary under test.
fn tldr_bin() -> &'static str {
    env!("CARGO_BIN_EXE_tldr")
}

/// The real corpus function: Flask tutorial `register` view.
fn flask_auth_path() -> &'static str {
    "/tmp/tldr_corpora/python-flask/examples/tutorial/flaskr/auth.py"
}

/// Run `tldr taint <file> <fn> -f json` and parse the JSON result.
fn run_taint_json(file: &str, function: &str) -> Value {
    let output = Command::new(tldr_bin())
        .args(["taint", file, function, "-f", "json"])
        .output()
        .expect("failed to spawn tldr taint");
    assert!(
        output.status.success(),
        "tldr taint exited non-zero for {function}: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("non-utf8 taint stdout");
    serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("invalid taint JSON: {e}\n{stdout}"))
}

/// Compute the union of every block's tainted-var set from the block-keyed map.
fn block_keyed_union(value: &Value) -> Vec<String> {
    let map = value
        .get("tainted_vars")
        .and_then(Value::as_object)
        .expect("tainted_vars object missing");
    let mut union: Vec<String> = map
        .values()
        .filter_map(Value::as_array)
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect();
    union.sort();
    union.dedup();
    union
}

/// Extract `tainted_vars_flat` as a `Vec<String>`.
fn flat_list(value: &Value) -> Vec<String> {
    value
        .get("tainted_vars_flat")
        .and_then(Value::as_array)
        .unwrap_or_else(|| {
            panic!(
                "tainted_vars_flat field missing from taint JSON: {}",
                serde_json::to_string_pretty(value).unwrap_or_default()
            )
        })
        .iter()
        .map(|v| {
            v.as_str()
                .expect("tainted_vars_flat must be an array of strings")
                .to_string()
        })
        .collect()
}

#[test]
fn corpus_present_for_test() {
    assert!(
        Path::new(flask_auth_path()).exists(),
        "expected corpus file at {} — populate /tmp/tldr_corpora/python-flask",
        flask_auth_path()
    );
}

/// The new field must be present on a function that produces taint.
#[test]
fn tainted_vars_flat_present_on_real_function() {
    let value = run_taint_json(flask_auth_path(), "register");
    assert!(
        value.get("tainted_vars_flat").is_some(),
        "tainted_vars_flat must be emitted for the `register` view"
    );
    let flat = flat_list(&value);
    assert!(
        !flat.is_empty(),
        "register threads request.form into db.execute, so flat taint set must be non-empty; got {flat:?}"
    );
}

/// The flat list must equal the sorted, deduped union of the block-keyed map.
#[test]
fn tainted_vars_flat_equals_sorted_union() {
    let value = run_taint_json(flask_auth_path(), "register");
    let flat = flat_list(&value);
    let union = block_keyed_union(&value);
    assert_eq!(
        flat, union,
        "tainted_vars_flat must be the sorted union of all blocks' tainted_vars"
    );
    // The real `register` view: username + password sources, error assigned in
    // the tainted-conditioned branch. These are the clean (suffix-stripped)
    // identifiers the union must contain.
    assert!(
        flat.contains(&"username".to_string()) && flat.contains(&"password".to_string()),
        "expected request.form-derived vars in flat taint set; got {flat:?}"
    );
}

/// The flat list must be sorted and free of duplicates (deterministic surface).
#[test]
fn tainted_vars_flat_sorted_and_deduped() {
    let value = run_taint_json(flask_auth_path(), "register");
    let flat = flat_list(&value);

    let mut expected_sorted = flat.clone();
    expected_sorted.sort();
    assert_eq!(flat, expected_sorted, "tainted_vars_flat must be sorted");

    let mut deduped = flat.clone();
    deduped.dedup();
    assert_eq!(
        flat, deduped,
        "tainted_vars_flat must contain no duplicates"
    );
}

/// Names must be clean: no `_<digits>` SSA version suffixes leak through.
#[test]
fn tainted_vars_flat_has_clean_names() {
    let value = run_taint_json(flask_auth_path(), "register");
    let flat = flat_list(&value);
    for name in &flat {
        if let Some(idx) = name.rfind('_') {
            let tail = &name[idx + 1..];
            assert!(
                !(!tail.is_empty() && tail.chars().all(|c| c.is_ascii_digit())),
                "tainted_vars_flat must strip SSA version suffixes; found `{name}`"
            );
        }
    }
}

/// Determinism: running twice yields the same ordering.
#[test]
fn tainted_vars_flat_is_deterministic() {
    let a = flat_list(&run_taint_json(flask_auth_path(), "register"));
    let b = flat_list(&run_taint_json(flask_auth_path(), "register"));
    assert_eq!(a, b, "tainted_vars_flat ordering must be deterministic");
}
