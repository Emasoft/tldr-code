//! fix-cl-12-vuln-dedup-v1 (v0.5.0 CL-12) — gaps IT3-luau-01 / IT3-luau-02
//!
//! ## Background
//!
//! `tldr vuln` (and `tldr secure`, which wraps it) emit one finding per taint
//! PATH. On the Luau C++ corpus, ~51 distinct argv-derived source paths all
//! converge on the SAME `(file, line, vuln_type, sink)` — a single
//! `PathTraversal` into the `fopen` sink at `CLI/src/Compile.cpp:703`.
//!
//! Pre-fix, `VulnArgs::run` sorted `filtered_findings` by `(file, line,
//! vuln_type)` (vuln.rs:272) but had NO following `dedup_by` on the semantic
//! key, so all 51 path-distinct-but-sink-identical findings survived to the
//! emitted report — inflating the security dashboard with 51 duplicates that
//! collapse to 1 unique vulnerability. `dedupe_overlap` only reconciles the
//! Rust line-scanner against the canonical pipeline; it does NOT collapse
//! intra-canonical duplicate taint paths.
//!
//! ## What this test pins
//!
//! For every `(file, line, vuln_type, sink-expression)` semantic key in the
//! emitted vuln report, AT MOST ONE finding survives. The sink expression is
//! the last `taint_flow` entry's `code_snippet` (the sink statement). The
//! same invariant holds for `secure`, which inherits the vuln findings.
//!
//! Verified-FAILS-first: before the fix, `vuln CLI/src/Compile.cpp` emits 51
//! findings collapsing to 1 unique semantic key.

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

/// Skip (pass vacuously) when a corpus is not present on this machine.
fn corpus_or_skip(path: &str) -> Option<PathBuf> {
    let p = PathBuf::from(path);
    if p.exists() {
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
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "tldr {:?} did not emit JSON: {e}\nstdout={}\nstderr={}",
            args,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

/// Semantic key for a vuln finding: (vuln_type, file, line, sink-expression).
/// The sink is the last `taint_flow` entry's `code_snippet`.
fn semantic_key(f: &Value) -> (String, String, u64, String) {
    let vt = f.get("vuln_type").and_then(Value::as_str).unwrap_or("").to_string();
    let file = f.get("file").and_then(Value::as_str).unwrap_or("").to_string();
    let line = f.get("line").and_then(Value::as_u64).unwrap_or(0);
    let sink = f
        .get("taint_flow")
        .and_then(Value::as_array)
        .and_then(|a| a.last())
        .and_then(|s| s.get("code_snippet"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    (vt, file, line, sink)
}

/// Assert no two findings share a `(vuln_type, file, line, sink)` key.
fn assert_deduped(findings: &[Value], ctx: &str) {
    use std::collections::HashSet;
    let mut seen: HashSet<(String, String, u64, String)> = HashSet::new();
    let mut dups = 0usize;
    for f in findings {
        let k = semantic_key(f);
        if !seen.insert(k.clone()) {
            dups += 1;
        }
    }
    assert_eq!(
        dups, 0,
        "{ctx}: {dups} duplicate findings on semantic key (vuln_type,file,line,sink); \
         total={} unique={}",
        findings.len(),
        seen.len()
    );
}

#[test]
fn vuln_dedups_identical_semantic_key_on_luau_compile_cpp() {
    let Some(corpus) = corpus_or_skip("/tmp/tldr_corpora/luau") else {
        return;
    };
    let target = corpus.join("CLI/src/Compile.cpp");
    if !target.exists() {
        eprintln!("SKIP: target not present: {}", target.display());
        return;
    }

    let report = run_json(&["vuln", target.to_str().unwrap(), "--format", "json"]);
    let findings = report
        .get("findings")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    // Pre-fix this is 51 findings on a single semantic key.
    assert!(
        !findings.is_empty(),
        "expected at least one PathTraversal finding on Compile.cpp"
    );
    assert_deduped(&findings, "vuln Compile.cpp");
}

#[test]
fn secure_inherits_vuln_dedup_on_luau_compile_cpp() {
    let Some(corpus) = corpus_or_skip("/tmp/tldr_corpora/luau") else {
        return;
    };
    let target = corpus.join("CLI/src/Compile.cpp");
    if !target.exists() {
        eprintln!("SKIP: target not present: {}", target.display());
        return;
    }

    let report = run_json(&["secure", target.to_str().unwrap(), "--format", "json"]);

    // `secure` nests the vuln report; locate any `findings` array carrying
    // vuln-shaped entries (vuln_type + taint_flow).
    let findings = locate_vuln_findings(&report);
    if findings.is_empty() {
        eprintln!("SKIP: secure emitted no vuln-shaped findings on this corpus");
        return;
    }
    assert_deduped(&findings, "secure Compile.cpp");
}

/// Recursively find an array of vuln-shaped findings (objects with both a
/// `vuln_type` and a `taint_flow` field) anywhere in the `secure` report.
fn locate_vuln_findings(v: &Value) -> Vec<Value> {
    match v {
        Value::Array(arr) => {
            let looks_vuln = arr.iter().any(|e| {
                e.get("vuln_type").is_some() && e.get("taint_flow").is_some()
            });
            if looks_vuln {
                return arr.clone();
            }
            for e in arr {
                let nested = locate_vuln_findings(e);
                if !nested.is_empty() {
                    return nested;
                }
            }
            Vec::new()
        }
        Value::Object(map) => {
            for (_, e) in map {
                let nested = locate_vuln_findings(e);
                if !nested.is_empty() {
                    return nested;
                }
            }
            Vec::new()
        }
        _ => Vec::new(),
    }
}
