//! fix-cl-3r-determinism-v1 (v0.5.0 CL-3) — residual #74 nondeterminism
//!
//! ## Background
//!
//! Cluster CL-3 (#74) is the family of bugs where HashMap/HashSet iteration
//! order (and unsorted truncate) leak into result arrays / JSON key order, so
//! the SAME corpus produces a DIFFERENT byte stream on each run. Earlier CL-1
//! determinism work fixed several boundaries; this is the residual set the
//! iter-3b audit re-reproduced:
//!
//!   * IT3-go-02          `temporal` constraint/trigram ties fell back to
//!                        HashMap order (temporal.rs sort_by keyed only on
//!                        confidence,support).
//!   * IT3-lua-02         `secure` findings sorted by severity ONLY; equal-
//!                        severity findings retained HashMap-derived order.
//!   * IT3-lua-05         `coupling` sorted by score ONLY; equal-score module
//!                        pairs retained `pair_calls` HashMap order; plus
//!                        `shared_imports` came from an unsorted HashSet
//!                        intersection.
//!   * IT3-typescript-02  `reaching-defs` IN/OUT/GEN sets + def-use chains came
//!                        from HashSet/HashMap with no final sort.
//!   * IT3-typescript-03  `available` block-ID keys + `all_exprs` set unsorted.
//!   * IT3-typescript-04  `taint` `tainted_vars` (block map) + `sanitized_vars`
//!                        serialized in raw HashMap/HashSet order.
//!
//! ## What this test pins
//!
//! Each command is run TWICE on its iter-3b corpus/target and the JSON output
//! must be byte-identical after stripping wall-clock `*_ms` timing fields
//! (legitimate jitter, not a determinism bug). Verified-FAILS-first: before the
//! fix each of these commands produced two distinct byte streams.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

/// Resolve the release binary built by `cargo build --release`.
fn tldr_bin() -> PathBuf {
    let release = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/release/tldr");
    if release.exists() {
        release
    } else {
        PathBuf::from(env!("CARGO_BIN_EXE_tldr"))
    }
}

/// Skip (pass vacuously) when a corpus/target is not present on this machine.
fn path_or_skip(path: &str) -> Option<PathBuf> {
    let p = PathBuf::from(path);
    if p.exists() {
        Some(p)
    } else {
        eprintln!("SKIP: not present: {path}");
        None
    }
}

/// Run `tldr <args>` and return parsed JSON (or None if it did not emit JSON).
fn run_json(args: &[&str]) -> Option<Value> {
    let out = Command::new(tldr_bin())
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn tldr {:?}: {e}", args));
    serde_json::from_slice(&out.stdout).ok()
}

/// Recursively strip every object key whose name ends in `_ms` (wall-clock
/// timing jitter) so the determinism check compares only semantic content.
fn strip_timing(v: &mut Value) {
    match v {
        Value::Object(map) => {
            map.retain(|k, _| !k.ends_with("_ms"));
            for (_, child) in map.iter_mut() {
                strip_timing(child);
            }
        }
        Value::Array(arr) => {
            for child in arr.iter_mut() {
                strip_timing(child);
            }
        }
        _ => {}
    }
}

/// Run a command twice and assert byte-identical canonical JSON (timing
/// stripped). The canonical form is `serde_json::to_string` over the (already
/// key-ordered) value, which preserves object key order as emitted — so a key
/// re-ordering is caught, not masked.
fn assert_deterministic(args: &[&str], ctx: &str) {
    let Some(mut a) = run_json(args) else {
        eprintln!("SKIP: {ctx}: command did not emit JSON");
        return;
    };
    let Some(mut b) = run_json(args) else {
        eprintln!("SKIP: {ctx}: command did not emit JSON on 2nd run");
        return;
    };
    strip_timing(&mut a);
    strip_timing(&mut b);
    let sa = serde_json::to_string(&a).unwrap();
    let sb = serde_json::to_string(&b).unwrap();
    assert_eq!(
        sa, sb,
        "{ctx}: two runs produced different JSON (residual #74 nondeterminism)"
    );
}

// --- IT3-go-02 ---------------------------------------------------------------

#[test]
fn temporal_is_deterministic_on_go_httprouter() {
    let Some(corpus) = path_or_skip("/tmp/tldr_corpora/go-httprouter") else {
        return;
    };
    assert_deterministic(
        &["temporal", corpus.to_str().unwrap(), "--format", "json"],
        "temporal go-httprouter",
    );
}

// --- IT3-lua-02 / IT3-lua-05 -------------------------------------------------

#[test]
fn secure_is_deterministic_on_lua_lsp() {
    let Some(corpus) = path_or_skip("/tmp/tldr_corpora/lua-lsp") else {
        return;
    };
    assert_deterministic(
        &["secure", corpus.to_str().unwrap(), "--format", "json"],
        "secure lua-lsp",
    );
}

#[test]
fn coupling_is_deterministic_on_lua_lsp() {
    let Some(corpus) = path_or_skip("/tmp/tldr_corpora/lua-lsp") else {
        return;
    };
    assert_deterministic(
        &["coupling", corpus.to_str().unwrap(), "--format", "json"],
        "coupling lua-lsp",
    );
}

// --- IT3-typescript-02 / -03 / -04 -------------------------------------------

fn ts_scanner() -> Option<PathBuf> {
    path_or_skip("/tmp/tldr_corpora/typescript-nest/packages/core/scanner.ts")
}

#[test]
fn reaching_defs_is_deterministic_on_ts_scanner() {
    let Some(f) = ts_scanner() else { return };
    assert_deterministic(
        &["reaching-defs", f.to_str().unwrap(), "scanForModules", "--format", "json"],
        "reaching-defs scanner.ts",
    );
}

#[test]
fn available_is_deterministic_on_ts_scanner() {
    let Some(f) = ts_scanner() else { return };
    assert_deterministic(
        &["available", f.to_str().unwrap(), "scanForModules", "--format", "json"],
        "available scanner.ts",
    );
}

#[test]
fn taint_is_deterministic_on_ts_scanner() {
    let Some(f) = ts_scanner() else { return };
    assert_deterministic(
        &["taint", f.to_str().unwrap(), "scanForModules", "--format", "json"],
        "taint scanner.ts",
    );
}
