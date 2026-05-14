//! M-014: dead-stores `live_vars_count` / `dead_stores_live_vars` defaults.
//!
//! Before v0.4.2, the dead-stores emitter set these optional fields to `null`
//! whenever `--compare` was not requested (which is the default for ~13 langs).
//! That made the JSON schema inconsistent — consumers had to special-case null.
//!
//! Fix (mechanical, cosmetic): emit `[]` / `0` defaults at the serialisation
//! boundary so the wire format is stable regardless of whether the live-vars
//! sub-analysis was wired or not.
//!
//! NOTE: Full per-lang live-variable analysis is parked as design (it requires
//! lexical-scope policy decisions per language). This test only pins the wire
//! defaults, not the analysis behaviour.

use serde_json::Value;
use std::path::Path;
use std::process::Command;

fn tldr_bin() -> &'static str {
    // The test harness invokes the crate binary directly.
    env!("CARGO_BIN_EXE_tldr")
}

fn run_dead_stores(file: &str, func: &str) -> Value {
    let output = Command::new(tldr_bin())
        .args(["dead-stores", file, func, "--format", "json"])
        .output()
        .unwrap_or_else(|e| panic!("failed to invoke tldr: {e}"));
    assert!(
        output.status.success(),
        "tldr dead-stores exited with {:?}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("tldr dead-stores emitted non-JSON: {e}\nstdout: {stdout}")
    })
}

fn assert_defaults(json: &Value, label: &str) {
    let lv = json
        .get("dead_stores_live_vars")
        .unwrap_or_else(|| panic!("[{label}] missing dead_stores_live_vars field"));
    assert!(
        !lv.is_null(),
        "[{label}] dead_stores_live_vars must NOT be null (got: {lv})"
    );
    assert!(
        lv.is_array(),
        "[{label}] dead_stores_live_vars must be an array (got: {lv})"
    );
    assert_eq!(
        lv.as_array().unwrap().len(),
        0,
        "[{label}] dead_stores_live_vars must be [] when --compare not requested"
    );

    let lvc = json
        .get("live_vars_count")
        .unwrap_or_else(|| panic!("[{label}] missing live_vars_count field"));
    assert!(
        !lvc.is_null(),
        "[{label}] live_vars_count must NOT be null (got: {lvc})"
    );
    assert_eq!(
        lvc.as_u64(),
        Some(0),
        "[{label}] live_vars_count must be 0 when --compare not requested"
    );
}

/// Create a tiny source fixture and run dead-stores on it.
fn assert_defaults_for(label: &str, ext: &str, source: &str, func: &str) {
    let tmp = std::env::temp_dir().join(format!(
        "tldr_m014_{}_{}_{}.{}",
        label,
        std::process::id(),
        // a small disambiguator so parallel runs don't collide
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
        ext
    ));
    std::fs::write(&tmp, source).unwrap();
    let json = run_dead_stores(tmp.to_str().unwrap(), func);
    assert_defaults(&json, label);
    let _ = std::fs::remove_file(&tmp);
}

#[test]
fn rust_dead_stores_defaults_emit_empty_not_null() {
    let src = r#"
pub fn sample(x: i32) -> i32 {
    let _y = 1;
    x + 1
}
"#;
    assert_defaults_for("rust", "rs", src, "sample");
}

#[test]
fn typescript_dead_stores_defaults_emit_empty_not_null() {
    let src = r#"
export function sample(x: number): number {
    const _y = 1;
    return x + 1;
}
"#;
    assert_defaults_for("typescript", "ts", src, "sample");
}

#[test]
fn javascript_dead_stores_defaults_emit_empty_not_null() {
    let src = r#"
function sample(x) {
    var _y = 1;
    return x + 1;
}
"#;
    assert_defaults_for("javascript", "js", src, "sample");
}

#[test]
fn c_dead_stores_defaults_emit_empty_not_null() {
    let src = r#"
int sample(int x) {
    int y = 1;
    return x + 1;
}
"#;
    assert_defaults_for("c", "c", src, "sample");
}

#[test]
fn go_dead_stores_defaults_emit_empty_not_null() {
    let src = r#"
package main

func sample(x int) int {
    y := 1
    _ = y
    return x + 1
}
"#;
    assert_defaults_for("go", "go", src, "sample");
}

#[test]
fn python_dead_stores_defaults_emit_empty_not_null() {
    let src = r#"
def sample(x):
    y = 1
    return x + 1
"#;
    assert_defaults_for("python", "py", src, "sample");
}

/// Real-world fixture matching the audit repros (TS ts-dom-gen / C c-sds).
/// Skipped automatically when repos aren't checked out locally.
#[test]
fn audit_fixtures_defaults_when_present() {
    let cases: &[(&str, &str, &str)] = &[
        ("ts-dom-gen", "/tmp/repos/ts-dom-gen/src/build/emitter.ts", "emitWebIdl"),
        ("c-sds", "/tmp/repos/c-sds/sds.c", "sdsnew"),
    ];
    for (label, path, func) in cases {
        if !Path::new(path).exists() {
            eprintln!("[skip {label}] fixture missing: {path}");
            continue;
        }
        let json = run_dead_stores(path, func);
        assert_defaults(&json, label);
    }
}
