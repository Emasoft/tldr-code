//! high-bundle-progress-determinism-coverage-v1 — regression tests for 5 HIGH UX bugs.
//!
//! Covers:
//!   N1  Progress messages must not pollute stdout when format is json/sarif/compact
//!       (auto-quiet mode kicks in for machine-readable formats).
//!   N2  `tldr calls` must be deterministic across runs on the same input.
//!   N3  `tldr health` must be deterministic across runs and json/text must agree.
//!   N4  `tldr diagnostics` `files_analyzed` counter must reflect the actual file count
//!       (was hard-coded to 1 regardless of directory size).
//!   N5  `tldr imports` must parse CommonJS `require('module')` calls in JS/TS.

use serde_json::Value;
use std::fs;
use std::process::Command;
use tempfile::TempDir;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

// =============================================================================
// N1: Progress messages must not pollute stdout under json/sarif/compact
// =============================================================================

/// Build a small Python project so commands have something real to chew on.
fn fixture_project() -> TempDir {
    let temp = TempDir::new().unwrap();
    let f = temp.path().join("svc.py");
    fs::write(
        &f,
        "class Service:\n    def fetch(self, id: int) -> str:\n        return helper(id)\n\ndef helper(x):\n    return str(x)\n",
    )
    .unwrap();
    let g = temp.path().join("util.py");
    fs::write(&g, "def util():\n    return 1\n").unwrap();
    temp
}

#[test]
fn n1_no_progress_on_json_stdout_for_complexity() {
    let project = fixture_project();
    let file = project.path().join("svc.py");

    let out = tldr_cmd()
        .args([
            "complexity",
            file.to_str().unwrap(),
            "helper",
            "--format",
            "json",
        ])
        .output()
        .expect("tldr complexity should run");
    assert!(out.status.success(), "complexity should succeed");

    let stdout = String::from_utf8_lossy(&out.stdout);
    // The first non-whitespace character must be `{` — JSON. No progress
    // banner ahead of it, no other lines before it.
    let trimmed = stdout.trim_start();
    assert!(
        trimmed.starts_with('{'),
        "stdout for --format json must start with '{{', got: {}",
        stdout
    );
    assert!(
        !stdout.contains("Calculating complexity"),
        "progress banner leaked into stdout: {}",
        stdout
    );
    // Verify the JSON parses cleanly — no preamble bytes.
    let _: Value = serde_json::from_str(&stdout).expect("stdout must be valid JSON");
}

#[test]
fn n1_no_progress_on_json_stdout_across_commands() {
    let project = fixture_project();
    let path = project.path();

    // Bind path strings up-front so the slice borrows live long enough.
    let path_str = path.to_str().unwrap().to_string();
    let svc_path = path.join("svc.py");
    let svc_str = svc_path.to_str().unwrap().to_string();

    // Commands that historically printed a progress banner. Each must, under
    // --format json, write JSON-only to stdout.
    let cases: Vec<Vec<&str>> = vec![
        vec!["calls", &path_str],
        vec!["structure", &path_str],
        vec!["loc", &path_str],
        vec!["imports", &svc_str],
        vec!["extract", &svc_str],
        vec!["smells", &path_str],
        vec!["dead", &path_str],
        vec!["debt", &path_str],
        vec!["complexity", &svc_str, "helper"],
        vec!["cognitive", &svc_str],
    ];

    for argv in &cases {
        let out = tldr_cmd()
            .args(argv)
            .args(["--format", "json"])
            .output()
            .unwrap_or_else(|e| panic!("tldr {:?} failed to launch: {}", argv, e));
        let stdout = String::from_utf8_lossy(&out.stdout);
        let trimmed = stdout.trim_start();
        // We accept either an object or a bare-array (some commands emit
        // arrays or empty results) — both must start with a JSON token.
        let first_byte = trimmed.chars().next().unwrap_or(' ');
        assert!(
            first_byte == '{' || first_byte == '[' || trimmed.is_empty(),
            "tldr {:?} stdout must start with JSON token, got: {}",
            argv,
            stdout
        );
        // No known progress prefixes.
        for banner in [
            "Calculating ",
            "Building call graph",
            "Analyzing ",
            "Detecting ",
            "Running diagnostics",
            "Parsing imports",
            "Extracting ",
            "Detecting code smells",
        ] {
            assert!(
                !stdout.contains(banner),
                "tldr {:?} leaked progress banner '{}' to stdout: {}",
                argv,
                banner,
                stdout
            );
        }
    }
}

// =============================================================================
// N2: `tldr calls` must be deterministic
// =============================================================================

/// Multi-file fixture so the call graph builder sees more than one file
/// (which is the path that surfaces the HashMap-iteration nondeterminism).
fn callgraph_fixture() -> TempDir {
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("a.py"),
        "from b import process\n\ndef main():\n    process(1)\n    helper()\n\ndef helper():\n    return 1\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("b.py"),
        "from c import deep\n\ndef process(x):\n    deep(x)\n    return x\n",
    )
    .unwrap();
    fs::write(temp.path().join("c.py"), "def deep(x):\n    return x * 2\n").unwrap();
    fs::write(
        temp.path().join("d.py"),
        "from a import main\n\ndef driver():\n    main()\n",
    )
    .unwrap();
    temp
}

#[test]
fn n2_calls_deterministic_total_edges() {
    let project = callgraph_fixture();

    let mut counts = Vec::new();
    let mut full_outputs = Vec::new();
    for _ in 0..3 {
        let out = tldr_cmd()
            .args([
                "calls",
                project.path().to_str().unwrap(),
                "--format",
                "json",
            ])
            .output()
            .expect("tldr calls should run");
        assert!(out.status.success(), "calls should succeed");
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let v: Value = serde_json::from_str(&stdout).expect("calls must emit JSON");
        let total = v
            .get("total_edges")
            .and_then(|x| x.as_u64())
            .expect("total_edges must be present");
        counts.push(total);
        full_outputs.push(stdout);
    }
    assert_eq!(
        counts[0], counts[1],
        "total_edges run1 vs run2 must match: {:?}",
        counts
    );
    assert_eq!(
        counts[1], counts[2],
        "total_edges run2 vs run3 must match: {:?}",
        counts
    );
    // The full byte stream must also be stable (edges are sorted).
    assert_eq!(
        full_outputs[0], full_outputs[1],
        "full JSON output must be byte-stable across runs"
    );
}

// =============================================================================
// N3: `tldr health` deterministic and json/text agree
// =============================================================================

#[test]
fn n3_health_format_consistency_and_determinism() {
    let project = callgraph_fixture();

    // Run JSON 3 times — must be identical.
    let mut json_runs = Vec::new();
    for _ in 0..3 {
        let out = tldr_cmd()
            .args([
                "health",
                project.path().to_str().unwrap(),
                "--format",
                "json",
            ])
            .output()
            .expect("tldr health should run");
        assert!(out.status.success(), "health should succeed");
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let v: Value = serde_json::from_str(&stdout).expect("health must emit JSON");
        let tight = v
            .get("summary")
            .and_then(|s| s.get("tight_coupling_pairs"))
            .and_then(|x| x.as_u64())
            .unwrap_or(0);
        json_runs.push(tight);
    }
    assert_eq!(
        json_runs[0], json_runs[1],
        "health json tight_coupling_pairs must match across runs: {:?}",
        json_runs
    );
    assert_eq!(json_runs[1], json_runs[2]);

    // Now run text format and make sure it agrees with the JSON value.
    let out = tldr_cmd()
        .args([
            "health",
            project.path().to_str().unwrap(),
            "--format",
            "text",
        ])
        .output()
        .expect("tldr health text should run");
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout).into_owned();

    if json_runs[0] > 0 {
        // Coupling line must mention the same number.
        let needle = format!("{} tightly coupled pairs", json_runs[0]);
        assert!(
            text.contains(&needle),
            "text format must report '{}' coupled pairs (matching json), got: {}",
            json_runs[0],
            text
        );
    } else {
        // No tight coupling — text should either say so or omit the line.
        assert!(
            !text.contains("tightly coupled pairs")
                || text.contains("0 tightly coupled pairs")
                || text.contains("no tight coupling detected"),
            "text format must agree with json that there are no tight pairs, got: {}",
            text
        );
    }
}

// =============================================================================
// N4: `tldr diagnostics` files_analyzed counter
// =============================================================================

#[test]
fn n4_diagnostics_files_analyzed_counter() {
    // Build a small Rust project — `cargo`/`clippy` is reliably present in CI
    // and on the developer machine. We only care about the file counter, not
    // whether any diagnostic actually fires.
    let temp = TempDir::new().unwrap();
    let src = temp.path().join("src");
    fs::create_dir_all(&src).unwrap();
    for n in 0..5 {
        fs::write(
            src.join(format!("mod_{}.rs", n)),
            "pub fn f() -> i32 { 1 }\n",
        )
        .unwrap();
    }
    fs::write(
        temp.path().join("Cargo.toml"),
        "[package]\nname=\"x\"\nversion=\"0.0.0\"\nedition=\"2021\"\n[lib]\npath=\"src/mod_0.rs\"\n",
    )
    .unwrap();

    let out = tldr_cmd()
        .args([
            "diagnostics",
            temp.path().to_str().unwrap(),
            "--format",
            "json",
            "--lang",
            "rust",
            // Avoid actually invoking heavy compilers in the test by
            // requesting a tool that may be unavailable; we still get a
            // DiagnosticsReport with the counter populated. If the tool is
            // missing, the command exits with code 60 and we skip — which
            // is acceptable for this counter test on machines without
            // rust-analyzer-style tools.
        ])
        .output()
        .expect("tldr diagnostics should launch");

    // Exit code 60 means no tool was installed for this language — that's a
    // CI-specific environment issue, not a bug in our counter logic. Skip
    // the assertion in that case so the test isn't flaky on minimal hosts.
    if out.status.code() == Some(60) {
        eprintln!("skipping n4 file-counter test: no diagnostic tool installed");
        return;
    }
    assert!(
        out.status.success() || out.status.code() == Some(1),
        "diagnostics should produce a report (exit 0 or 1), got {:?}, stderr={}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: Value = serde_json::from_str(&stdout).expect("diagnostics must emit JSON");
    let files_analyzed = v
        .get("files_analyzed")
        .and_then(|x| x.as_u64())
        .expect("files_analyzed must be present");

    // We wrote 5 files; the counter must reflect more than 1.
    assert!(
        files_analyzed > 1,
        "files_analyzed must reflect actual scan size (>1 for multi-file project), got {}",
        files_analyzed
    );
}

// =============================================================================
// N5: `tldr imports` parses CommonJS require()
// =============================================================================

#[test]
fn n5_imports_parses_commonjs_require() {
    let temp = TempDir::new().unwrap();
    let f = temp.path().join("index.js");
    fs::write(
        &f,
        "'use strict';\n\
         const express = require('express');\n\
         const path = require('path');\n\
         module.exports = require('./lib/express');\n",
    )
    .unwrap();

    let out = tldr_cmd()
        .args(["imports", f.to_str().unwrap(), "--format", "json"])
        .output()
        .expect("tldr imports should run");
    assert!(out.status.success(), "imports should succeed");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: Value = serde_json::from_str(&stdout).expect("imports must emit JSON");
    let imports = v
        .get("imports")
        .and_then(|x| x.as_array())
        .expect("imports field must be an array");

    let modules: Vec<String> = imports
        .iter()
        .filter_map(|i| i.get("module").and_then(|m| m.as_str()).map(str::to_string))
        .collect();

    assert!(
        modules.contains(&"express".to_string()),
        "must extract require('express'), got: {:?}",
        modules
    );
    assert!(
        modules.contains(&"path".to_string()),
        "must extract require('path'), got: {:?}",
        modules
    );
    assert!(
        modules.contains(&"./lib/express".to_string()),
        "must extract require('./lib/express'), got: {:?}",
        modules
    );
}

#[test]
fn n5_imports_skips_dynamic_require() {
    // Dynamic require where the argument isn't a literal string must NOT
    // emit an import (we have no resolvable module name).
    let temp = TempDir::new().unwrap();
    let f = temp.path().join("dyn.js");
    fs::write(&f, "const name = 'lodash';\nconst mod = require(name);\n").unwrap();

    let out = tldr_cmd()
        .args(["imports", f.to_str().unwrap(), "--format", "json"])
        .output()
        .expect("tldr imports should run");
    assert!(out.status.success());

    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: Value = serde_json::from_str(&stdout).unwrap();
    let imports = v.get("imports").and_then(|x| x.as_array()).unwrap();
    let modules: Vec<String> = imports
        .iter()
        .filter_map(|i| i.get("module").and_then(|m| m.as_str()).map(str::to_string))
        .collect();

    assert!(
        !modules.contains(&"name".to_string()),
        "must not emit identifier as module name: {:?}",
        modules
    );
}
