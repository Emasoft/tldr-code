//! hubs-line-population-v1 — regression tests for the bug where every
//! hub returned by `tldr hubs` had `function_ref.line: 0`.
//!
//! Pre-fix repro on the Flask repo:
//!
//! ```text
//! $ tldr hubs /tmp/repos/flask --quiet | jq '[.hubs[].function_ref.line] | unique'
//! [0]
//! ```
//!
//! `Scaffold.route` is defined at `src/flask/sansio/scaffold.py:336`, but the
//! emitted `function_ref.line` was always `0`. The cause: the call-graph
//! builder constructs `FunctionRef` from edges without line info
//! (`graph_utils::collect_nodes`), and the hubs analysis layer never
//! reconciled lines against the AST extractor.
//!
//! Fix (`compute_hub_report_with_lines` + `enumerate_function_lines`):
//! the hubs CLI now walks the project, parses each file with the canonical
//! AST extractor, and populates `function_ref.line` from the result.
//!
//! These tests assert the lines are populated for at least three languages
//! (Python, Rust, JavaScript) on small fixture projects with known function
//! line numbers.

use serde_json::Value;
use std::fs;
use std::process::Command;
use tempfile::TempDir;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

/// Run `tldr hubs --quiet --format json` against `path` and parse the JSON.
fn run_hubs_json(path: &std::path::Path) -> Value {
    let output = tldr_cmd()
        .args([
            "hubs",
            path.to_str().unwrap(),
            "--quiet",
            "--format",
            "json",
        ])
        .output()
        .expect("failed to run tldr hubs");
    assert!(
        output.status.success(),
        "tldr hubs failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8(output.stdout).expect("non-utf8 stdout");
    serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("invalid JSON from tldr hubs: {e}\n--- stdout ---\n{stdout}"))
}

/// Find the hub entry with the given `name` in the JSON report.
fn find_hub<'a>(json: &'a Value, name: &str) -> Option<&'a Value> {
    json["hubs"]
        .as_array()?
        .iter()
        .find(|h| h["function_ref"]["name"] == name || h["name"] == name)
}

// =============================================================================
// Python: function on a known line gets a populated `function_ref.line`.
// =============================================================================

#[test]
fn test_hubs_line_populated_python() {
    let temp = TempDir::new().unwrap();

    // helper(...) is defined on line 4 of util.py, called from many places.
    // The leading newline keeps `def helper` on a non-1 line so a
    // never-populated `0` would not coincidentally pass.
    fs::write(
        temp.path().join("util.py"),
        "\n\n\ndef helper(x):\n    return x * 2\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("a.py"),
        "from util import helper\n\ndef caller_a():\n    return helper(1)\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("b.py"),
        "from util import helper\n\ndef caller_b():\n    return helper(2)\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("c.py"),
        "from util import helper\n\ndef caller_c():\n    return helper(3)\n",
    )
    .unwrap();

    let json = run_hubs_json(temp.path());

    let hub = find_hub(&json, "helper").unwrap_or_else(|| {
        panic!(
            "`helper` not found in hubs report:\n{}",
            serde_json::to_string_pretty(&json).unwrap()
        )
    });
    let line = hub["function_ref"]["line"]
        .as_u64()
        .expect("function_ref.line must be a number");
    assert_eq!(
        line,
        4,
        "expected `helper` at line 4, got line={line}, hub={}",
        serde_json::to_string_pretty(hub).unwrap()
    );

    // No hub should have line == 0 — the whole point of this milestone.
    let zero_lines: Vec<&Value> = json["hubs"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|h| h["function_ref"]["line"].as_u64() == Some(0))
        .collect();
    assert!(
        zero_lines.is_empty(),
        "found {} hubs with line=0, expected none:\n{}",
        zero_lines.len(),
        serde_json::to_string_pretty(&zero_lines).unwrap()
    );
}

// =============================================================================
// Rust: standalone function at a known line gets a populated line.
// =============================================================================

#[test]
fn test_hubs_line_populated_rust() {
    let temp = TempDir::new().unwrap();
    fs::create_dir(temp.path().join("src")).unwrap();

    // `helper` defined on line 5 of lib.rs.
    fs::write(
        temp.path().join("src").join("lib.rs"),
        "// padding\n// padding\n// padding\n\npub fn helper(x: i32) -> i32 { x * 2 }\n\npub fn caller_a() -> i32 { helper(1) }\npub fn caller_b() -> i32 { helper(2) }\npub fn caller_c() -> i32 { helper(3) }\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("Cargo.toml"),
        "[package]\nname=\"hubs_fixture\"\nversion=\"0.1.0\"\nedition=\"2021\"\n\n[lib]\npath=\"src/lib.rs\"\n",
    )
    .unwrap();

    let output = tldr_cmd()
        .args([
            "hubs",
            temp.path().to_str().unwrap(),
            "--lang",
            "rust",
            "--quiet",
            "--format",
            "json",
        ])
        .output()
        .expect("failed to run tldr hubs");
    assert!(
        output.status.success(),
        "tldr hubs (rust) failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();

    let hub = find_hub(&json, "helper").unwrap_or_else(|| {
        panic!(
            "`helper` not found in hubs report:\n{}",
            serde_json::to_string_pretty(&json).unwrap()
        )
    });
    let line = hub["function_ref"]["line"]
        .as_u64()
        .expect("function_ref.line must be a number");
    assert_eq!(line, 5, "expected `helper` at line 5, got {line}");

    let zero_lines = json["hubs"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|h| h["function_ref"]["line"].as_u64() == Some(0))
        .count();
    assert_eq!(zero_lines, 0, "{zero_lines} hubs still had line=0");
}

// =============================================================================
// JavaScript: function declarations at known lines get populated lines.
// =============================================================================

#[test]
fn test_hubs_line_populated_javascript() {
    let temp = TempDir::new().unwrap();

    // `helper` declared on line 3 of util.js (ESM modules — the test uses
    // ESM `import`/`export` because that's the import dialect the call-graph
    // builder resolves cross-file).
    fs::write(
        temp.path().join("util.js"),
        "// header\n\nexport function helper(x) { return x * 2; }\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("a.js"),
        "import { helper } from './util.js';\nexport function caller_a() { return helper(1); }\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("b.js"),
        "import { helper } from './util.js';\nexport function caller_b() { return helper(2); }\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("c.js"),
        "import { helper } from './util.js';\nexport function caller_c() { return helper(3); }\n",
    )
    .unwrap();

    let output = tldr_cmd()
        .args([
            "hubs",
            temp.path().to_str().unwrap(),
            "--lang",
            "javascript",
            "--quiet",
            "--format",
            "json",
        ])
        .output()
        .expect("failed to run tldr hubs");
    assert!(
        output.status.success(),
        "tldr hubs (js) failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();

    // The exact identity (helper is the hub) is enough to check for line
    // population. Some node may match by qualified name vs bare; accept
    // either as long as the line is non-zero AND matches the source.
    let hub = find_hub(&json, "helper").unwrap_or_else(|| {
        panic!(
            "`helper` not found in hubs report:\n{}",
            serde_json::to_string_pretty(&json).unwrap()
        )
    });
    let line = hub["function_ref"]["line"]
        .as_u64()
        .expect("function_ref.line must be a number");
    assert_eq!(line, 3, "expected `helper` at line 3, got {line}");

    // Crucially: no hub may have line == 0.
    let zero_lines = json["hubs"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|h| h["function_ref"]["line"].as_u64() == Some(0))
        .count();
    assert_eq!(zero_lines, 0, "{zero_lines} hubs still had line=0");
}

// =============================================================================
// Python class method: `Class.method` qualified hub names get the right line.
// =============================================================================

#[test]
fn test_hubs_line_populated_python_class_method() {
    let temp = TempDir::new().unwrap();

    // `Scaffold.route` defined on line 5 of scaffold.py — this is the exact
    // shape of the original Flask bug ('Scaffold.route' had line=0 instead
    // of 336).
    fs::write(
        temp.path().join("scaffold.py"),
        "\n\nclass Scaffold:\n    def __init__(self):\n        pass\n\n    def route(self, rule):\n        return rule\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("a.py"),
        "from scaffold import Scaffold\n\ndef use_a():\n    return Scaffold().route('/a')\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("b.py"),
        "from scaffold import Scaffold\n\ndef use_b():\n    return Scaffold().route('/b')\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("c.py"),
        "from scaffold import Scaffold\n\ndef use_c():\n    return Scaffold().route('/c')\n",
    )
    .unwrap();

    let json = run_hubs_json(temp.path());

    // The hub may be recorded as either `Scaffold.route` (qualified) or
    // `route` (bare) depending on the call-graph builder's name policy.
    // Either is acceptable so long as the line is the actual definition
    // line for `def route` (line 7).
    let hubs = json["hubs"].as_array().unwrap();
    let route_hub = hubs
        .iter()
        .find(|h| {
            let name = h["function_ref"]["name"].as_str().unwrap_or("");
            name == "Scaffold.route" || name == "route"
        })
        .unwrap_or_else(|| {
            panic!(
                "neither `Scaffold.route` nor `route` was a hub:\n{}",
                serde_json::to_string_pretty(&json).unwrap()
            )
        });

    let line = route_hub["function_ref"]["line"]
        .as_u64()
        .expect("function_ref.line must be a number");
    assert_eq!(
        line,
        7,
        "expected `route` at line 7, got line={line}, hub={}",
        serde_json::to_string_pretty(route_hub).unwrap()
    );
}
