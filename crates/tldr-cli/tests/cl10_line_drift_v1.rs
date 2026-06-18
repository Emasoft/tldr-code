//! cl10-method-line-drift-v1 (v0.5.0 CL-10) — GH #81
//!
//! Regression test for method/function line-attribution drift to a leading
//! annotation / attribute line.
//!
//! ## Background
//!
//! `decl_keyword_line_from_node` (ast::extract) is the AST-only normaliser
//! that returns the line of the decl keyword (`func` / `public void Foo` /
//! `class`) rather than the line of a leading `@Annotation` (Java) or
//! `@attribute` (Swift). The `extract` / `explain` / `slice` pipelines
//! already route through it, and (M-109) `structure` adopted it — but only
//! gated on `Language::Java | Language::Solidity`.
//!
//! Three pipelines were observed to still drift to the annotation/attribute
//! line for the SAME symbol that `extract` attributes to the decl-keyword
//! line:
//!
//!   1. `structure` for **Swift** — the gate in `collect_definitions`
//!      excluded Swift, so `@inlinable`-decorated methods reported the
//!      attribute line.
//!   2. `cognitive` for **Java AND Swift** — used the bare
//!      `node.start_position()`.
//!   3. `contracts` for **Java AND Swift** — the per-condition `source_line`
//!      was derived from the bare `func.start_position()`.
//!
//! ## What this test pins
//!
//! For real corpora symbols whose decl keyword is preceded by one or more
//! annotation/attribute lines, the line reported by `structure`,
//! `cognitive`, and `contracts` must AGREE with the line reported by
//! `extract` (the source of truth). The test drives the release binary
//! against `/tmp/tldr_corpora/swift-collections` and
//! `/tmp/tldr_corpora/java-petclinic`.
//!
//! Verified-FAILS-first: before the fix, Swift `structure`/`cognitive` and
//! Java/Swift `cognitive`/`contracts` report the annotation/attribute line.

/// True when `p` exists AND contains at least one non-`.git` regular file
/// (or is itself a regular file). Corpus dirs may be present as empty
/// skeletons (git clone with no working tree) where `Path::exists()` is
/// `true` but analysis sees 0 files; these tests must skip in that case.
#[allow(dead_code)]
fn corpus_ready<P: AsRef<std::path::Path>>(p: P) -> bool {
    fn walk(p: &std::path::Path, depth: usize) -> bool {
        if depth > 8 { return false; }
        let Ok(rd) = std::fs::read_dir(p) else { return false; };
        for entry in rd.flatten() {
            let path = entry.path();
            if path.file_name().and_then(|n| n.to_str()) == Some(".git") { continue; }
            match entry.file_type() {
                Ok(ft) if ft.is_file() => return true,
                Ok(ft) if ft.is_dir() => { if walk(&path, depth + 1) { return true; } }
                _ => {}
            }
        }
        false
    }
    let root = p.as_ref();
    if root.is_file() { return true; }
    root.exists() && walk(root, 0)
}


use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

/// Resolve the release binary built by `cargo build --release`.
fn tldr_bin() -> PathBuf {
    // CARGO_BIN_EXE_tldr points at the test-profile build; we want the
    // release binary the cluster spec asks us to exercise. Fall back to the
    // env var if the release path is missing.
    let release = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/release/tldr");
    if release.exists() {
        release
    } else {
        PathBuf::from(env!("CARGO_BIN_EXE_tldr"))
    }
}

/// Skip (pass vacuously) when a corpus is not present on this machine.
fn corpus_or_skip(path: &str) -> Option<PathBuf> {
    let p = PathBuf::from(path);
    if corpus_ready(&p) {
        Some(p)
    } else {
        eprintln!("SKIP: corpus not present: {path}");
        None
    }
}

fn run_json(args: &[&str]) -> Value {
    let out = Command::new(tldr_bin())
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn tldr {:?}: {e}", args));
    assert!(
        out.status.success() || !out.stdout.is_empty(),
        "tldr {:?} failed: status={:?} stderr={}",
        args,
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "tldr {:?} did not emit JSON: {e}\nstdout={}\nstderr={}",
            args,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

/// Recursively find the first object having `name == target` that also carries
/// a `line` key; return that `line`.
fn find_line_by_name(v: &Value, target: &str, line_key: &str) -> Option<u64> {
    match v {
        Value::Object(map) => {
            if map.get("name").and_then(|n| n.as_str()) == Some(target) {
                if let Some(l) = map.get(line_key).and_then(|l| l.as_u64()) {
                    return Some(l);
                }
            }
            for child in map.values() {
                if let Some(l) = find_line_by_name(child, target, line_key) {
                    return Some(l);
                }
            }
            None
        }
        Value::Array(arr) => {
            for child in arr {
                if let Some(l) = find_line_by_name(child, target, line_key) {
                    return Some(l);
                }
            }
            None
        }
        _ => None,
    }
}

/// `extract` line for `symbol` in `file` (the source-of-truth decl-keyword line).
fn extract_line(file: &Path, symbol: &str) -> u64 {
    let v = run_json(&["extract", file.to_str().unwrap(), "--format", "json"]);
    find_line_by_name(&v, symbol, "line")
        .unwrap_or_else(|| panic!("extract: symbol `{symbol}` not found in {}", file.display()))
}

/// `structure` line for a method named `symbol` (searches method_infos + definitions).
fn structure_line(file: &Path, symbol: &str) -> u64 {
    let v = run_json(&["structure", file.to_str().unwrap(), "--format", "json"]);
    find_line_by_name(&v, symbol, "line")
        .or_else(|| find_line_by_name(&v, symbol, "line_start"))
        .unwrap_or_else(|| panic!("structure: symbol `{symbol}` not found in {}", file.display()))
}

/// `cognitive` line for `symbol`.
fn cognitive_line(file: &Path, symbol: &str) -> u64 {
    let v = run_json(&["cognitive", file.to_str().unwrap(), "--format", "json"]);
    find_line_by_name(&v, symbol, "line")
        .unwrap_or_else(|| panic!("cognitive: symbol `{symbol}` not found in {}", file.display()))
}

/// Minimum `source_line` across all contract conditions for `symbol`. The
/// per-function conditions are all anchored to the function's decl line, so
/// the minimum is the function line we care about. Returns None when the
/// function has no conditions (e.g. no params / no return type).
fn contracts_min_condition_line(file: &Path, symbol: &str) -> Option<u64> {
    let v = run_json(&[
        "contracts",
        file.to_str().unwrap(),
        symbol,
        "--format",
        "json",
    ]);
    let mut min: Option<u64> = None;
    for key in ["preconditions", "postconditions", "invariants"] {
        if let Some(arr) = v.get(key).and_then(|a| a.as_array()) {
            for cond in arr {
                if let Some(l) = cond
                    .get("source_line")
                    .and_then(|l| l.as_u64())
                    .or_else(|| cond.get("line").and_then(|l| l.as_u64()))
                {
                    min = Some(min.map_or(l, |m| m.min(l)));
                }
            }
        }
    }
    min
}

// =============================================================================
// SWIFT: structure / cognitive / contracts must agree with extract
// =============================================================================

#[test]
fn cl10_swift_structure_cognitive_contracts_agree_with_extract() {
    let Some(root) = corpus_or_skip("/tmp/tldr_corpora/swift-collections") else {
        return;
    };
    let file = root
        .join("Sources/SortedCollections/BTree/_BTree.swift");
    assert!(
        file.exists(),
        "expected fixture file present in corpus: {}",
        file.display()
    );

    // `invalidateIndices` is preceded by `@inlinable` (151) + `@inline(__always)`
    // (152); the `internal mutating func` keyword is on 153.
    let sym_noparam = "invalidateIndices";
    let extract_l = extract_line(&file, sym_noparam);

    let structure_l = structure_line(&file, sym_noparam);
    assert_eq!(
        structure_l, extract_l,
        "DRIFT(swift/structure): `{sym_noparam}` structure={structure_l} extract={extract_l} \
         (structure must report the decl-keyword line, not the @attribute line)"
    );

    let cognitive_l = cognitive_line(&file, sym_noparam);
    assert_eq!(
        cognitive_l, extract_l,
        "DRIFT(swift/cognitive): `{sym_noparam}` cognitive={cognitive_l} extract={extract_l}"
    );

    // `updateAnyValue` is preceded by `@inlinable` (169) + `@discardableResult`
    // (170); the `internal mutating func` keyword is on 171. It has typed
    // params + a return type so it surfaces contract conditions.
    let sym_param = "updateAnyValue";
    let extract_param_l = extract_line(&file, sym_param);

    assert_eq!(
        structure_line(&file, sym_param),
        extract_param_l,
        "DRIFT(swift/structure): `{sym_param}`"
    );
    assert_eq!(
        cognitive_line(&file, sym_param),
        extract_param_l,
        "DRIFT(swift/cognitive): `{sym_param}`"
    );

    let contracts_l = contracts_min_condition_line(&file, sym_param)
        .expect("updateAnyValue should surface contract conditions (typed params / return)");
    assert_eq!(
        contracts_l, extract_param_l,
        "DRIFT(swift/contracts): `{sym_param}` contracts source_line={contracts_l} \
         extract={extract_param_l} (conditions must anchor to the func keyword line, \
         not the @attribute line)"
    );
}

// =============================================================================
// JAVA: cognitive / contracts must agree with extract (structure already fixed)
// =============================================================================

#[test]
fn cl10_java_cognitive_contracts_agree_with_extract() {
    let Some(root) = corpus_or_skip("/tmp/tldr_corpora/java-petclinic") else {
        return;
    };
    let file = root.join(
        "src/main/java/org/springframework/samples/petclinic/PetClinicRuntimeHints.java",
    );
    assert!(
        file.exists(),
        "expected fixture file present in corpus: {}",
        file.display()
    );

    // `registerHints` is preceded by `@Override` (27); the `public void`
    // decl keyword is on 28. It takes typed params so it surfaces contract
    // conditions.
    let sym = "registerHints";
    let extract_l = extract_line(&file, sym);

    // structure already routes Java through the normaliser (M-109) — assert
    // it stays correct as a regression guard.
    assert_eq!(
        structure_line(&file, sym),
        extract_l,
        "REGRESSION(java/structure): `{sym}` drifted"
    );

    let cognitive_l = cognitive_line(&file, sym);
    assert_eq!(
        cognitive_l, extract_l,
        "DRIFT(java/cognitive): `{sym}` cognitive={cognitive_l} extract={extract_l} \
         (must report the decl-keyword line, not the @Override line)"
    );

    let contracts_l = contracts_min_condition_line(&file, sym)
        .expect("registerHints has typed params -> should surface contract conditions");
    assert_eq!(
        contracts_l, extract_l,
        "DRIFT(java/contracts): `{sym}` contracts source_line={contracts_l} \
         extract={extract_l} (conditions must anchor to the decl-keyword line)"
    );
}
