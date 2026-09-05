//! api-check-and-patterns-accuracy-v1 (P11.BUG-AGG-6, AGG-7, AGG-10)
//!
//! Three regressions closed in this milestone:
//!
//! 1. **BUG-AGG-6 (MED)** `tldr api-check` previously had no defense-in-depth
//!    gate ensuring a JS rule (`JSON.parse`/`parseInt`/`eval`) could not fire
//!    against a `.cpp` file. The primary `detect_language` dispatch already
//!    restricted each file to its language's rule set, but this milestone
//!    adds an explicit per-rule applicability check that backs up the
//!    dispatcher.
//! 2. **BUG-AGG-7 (MED)** `tldr patterns` was mis-classifying repos like
//!    `cpp-tinyxml2` as JavaScript-majority because doxygen-generated `docs/`
//!    contained 63 `.js` files vs 3 authored `.cpp` files. The walker now
//!    excludes common generated/vendored artefact directories AND uses a
//!    `doxygen.css` sentinel to detect ambiguously-named generator output
//!    inside a `docs/` directory.
//! 3. **BUG-AGG-10 (LOW)** `tldr api-check`'s C/C++ scanner matched
//!    `sprintf(...)` text inside `/* ... */` block comments. The scanner
//!    now tracks block-comment state across lines and skips matches that
//!    live inside a block comment.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;
use tempfile::TempDir;

fn tldr_bin() -> PathBuf {
    // Mirror the convention used by the other integration tests in this
    // crate: prefer the workspace `target/release/tldr` artefact built
    // by `cargo build --release`, with a fallback to `cargo run` if
    // the binary isn't present.
    let mut candidate = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    candidate.pop(); // crates/tldr-cli -> crates
    candidate.pop(); // crates -> repo root
    candidate.push("target/release/tldr");
    // why: Windows builds "tldr.exe", not "tldr" -- without this the
    // `bin.exists()` check below always fails on Windows and the whole
    // suite aborts via assert! before any test body runs.
    if cfg!(windows) {
        candidate.set_extension("exe");
    }
    candidate
}

fn run_tldr(args: &[&str]) -> (String, String, bool) {
    let bin = tldr_bin();
    assert!(
        bin.exists(),
        "expected release tldr binary at {} (run `cargo build --release --features semantic`)",
        bin.display()
    );
    let output = Command::new(&bin)
        .args(args)
        .output()
        .expect("failed to execute tldr binary");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (stdout, stderr, output.status.success())
}

fn write(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, contents).unwrap();
}

// =============================================================================
// BUG-AGG-6: per-rule applicable_languages gate
// =============================================================================

#[test]
fn test_api_check_skips_js_rules_on_cpp_files() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    write(
        &root.join("src/main.cpp"),
        "#include <cstdio>\nclass Foo {};\nint main(){ return 0; }\n",
    );
    write(
        &root.join("src/util.js"),
        "const data = JSON.parse(input);\nconst n = parseInt(s);\n",
    );

    let (stdout, _stderr, ok) = run_tldr(&[
        "api-check",
        root.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert!(ok, "tldr api-check should exit 0, stdout={stdout}");

    let report: Value = serde_json::from_str(&stdout).expect("valid JSON");
    let findings = report
        .get("findings")
        .and_then(|v| v.as_array())
        .expect("findings array");

    // Collect rule_ids per file.
    let mut cpp_rules: Vec<String> = Vec::new();
    let mut js_rules: Vec<String> = Vec::new();
    for f in findings {
        let file = f.get("file").and_then(|v| v.as_str()).unwrap_or("");
        let rule_id = f
            .get("rule")
            .and_then(|r| r.get("id"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if file.ends_with(".cpp") {
            cpp_rules.push(rule_id);
        } else if file.ends_with(".js") {
            js_rules.push(rule_id);
        }
    }

    // Validation: no JS rule fires on a .cpp file.
    for r in &cpp_rules {
        assert!(
            !r.starts_with("JS"),
            "JS rule {r} must not fire on .cpp file (BUG-AGG-6 regression)"
        );
    }

    // Sanity: the JS file SHOULD see at least one JS finding (JSON.parse
    // and/or parseInt) so we know the gate didn't accidentally suppress
    // legitimate matches.
    assert!(
        js_rules.iter().any(|r| r.starts_with("JS")),
        "expected at least one JS rule to fire on .js file (got {js_rules:?})"
    );
}

// =============================================================================
// BUG-AGG-10: block-comment false positive in C
// =============================================================================

#[test]
fn test_api_check_no_false_positive_in_c_comments() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let src = "\
#include <stdio.h>

/* This function is safe; it does
 * not rely on sprintf() family functions
 * because they are unbounded.
 */
int safe_format(char *buf, int n) {
    return n;
}
";
    write(&root.join("src/sds.c"), src);

    let (stdout, _stderr, ok) = run_tldr(&[
        "api-check",
        root.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert!(ok, "tldr api-check should exit 0, stdout={stdout}");

    let report: Value = serde_json::from_str(&stdout).expect("valid JSON");
    let findings = report
        .get("findings")
        .and_then(|v| v.as_array())
        .expect("findings array");

    let sprintf_findings: Vec<&Value> = findings
        .iter()
        .filter(|f| {
            f.get("rule")
                .and_then(|r| r.get("id"))
                .and_then(|v| v.as_str())
                == Some("C003")
        })
        .collect();

    assert!(
        sprintf_findings.is_empty(),
        "C003 sprintf-call must NOT fire on a `sprintf()` mention inside \
         a /* ... */ block comment (BUG-AGG-10 regression). \
         Got {} findings: {:#?}",
        sprintf_findings.len(),
        sprintf_findings
    );
}

#[test]
fn test_api_check_real_sprintf_still_flagged() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let src = "\
#include <stdio.h>
int format_num(char *buf, int n) {
    sprintf(buf, \"%d\", n);
    return 0;
}
";
    write(&root.join("src/format.c"), src);

    let (stdout, _stderr, ok) = run_tldr(&[
        "api-check",
        root.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert!(ok, "tldr api-check should exit 0, stdout={stdout}");

    let report: Value = serde_json::from_str(&stdout).expect("valid JSON");
    let findings = report
        .get("findings")
        .and_then(|v| v.as_array())
        .expect("findings array");

    let has_c003 = findings.iter().any(|f| {
        f.get("rule")
            .and_then(|r| r.get("id"))
            .and_then(|v| v.as_str())
            == Some("C003")
    });

    assert!(
        has_c003,
        "C003 sprintf-call MUST still fire on a real `sprintf()` call \
         in a .c file (BUG-AGG-10 must not regress real detection). \
         findings={findings:#?}"
    );
}

// =============================================================================
// BUG-AGG-7: walker default-ignore for vendored/generated dirs
// =============================================================================

#[test]
fn test_patterns_skips_default_ignore_dirs() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    // Authored source: 1 .cpp file
    write(
        &root.join("src/main.cpp"),
        "#include <iostream>\nint main(){ std::cout << 1; return 0; }\n",
    );
    // Generated artefacts that should be ignored:
    // - dox/ (doxygen alt dir name) with JS files
    write(&root.join("dox/foo.js"), "const x = 1;\n");
    write(&root.join("dox/bar.js"), "const y = 2;\n");
    // - node_modules/ with JS files
    write(&root.join("node_modules/lib/baz.js"), "module.exports = {};\n");
    // - docs/ with doxygen sentinel + JS files (sentinel-detection path)
    write(&root.join("docs/doxygen.css"), "/* doxygen */\n");
    write(&root.join("docs/menu.js"), "var menu = [];\n");
    write(&root.join("docs/search/search.js"), "var idx = [];\n");

    let (stdout, _stderr, ok) = run_tldr(&[
        "patterns",
        root.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert!(ok, "tldr patterns should exit 0, stdout={stdout}");

    let report: Value = serde_json::from_str(&stdout).expect("valid JSON");
    let dist = report
        .get("metadata")
        .and_then(|m| m.get("language_distribution"))
        .expect("metadata.language_distribution");
    let by_lang = dist
        .get("files_by_language")
        .and_then(|v| v.as_object())
        .expect("files_by_language object");

    let cpp_count = by_lang.get("cpp").and_then(|v| v.as_u64()).unwrap_or(0);
    let js_count = by_lang
        .get("javascript")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    assert!(
        cpp_count >= 1,
        "expected cpp >= 1 in files_by_language (got {cpp_count}); \
         dist={dist:#?}"
    );
    assert_eq!(
        js_count, 0,
        "expected javascript = 0 (all JS files were in default-ignore \
         dirs: dox/, node_modules/, docs/ with doxygen.css sentinel); \
         got {js_count}; dist={dist:#?}"
    );
}

#[test]
fn test_patterns_real_repo_cpp_tinyxml2() {
    let real_repo = Path::new("/tmp/repos/cpp-tinyxml2");
    if !real_repo.exists() {
        eprintln!(
            "skipping test_patterns_real_repo_cpp_tinyxml2: {} not present",
            real_repo.display()
        );
        return;
    }

    let (stdout, _stderr, ok) = run_tldr(&[
        "patterns",
        real_repo.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert!(ok, "tldr patterns should exit 0, stdout={stdout}");

    let report: Value = serde_json::from_str(&stdout).expect("valid JSON");
    let dist = report
        .get("metadata")
        .and_then(|m| m.get("language_distribution"))
        .expect("metadata.language_distribution");
    let by_lang = dist
        .get("files_by_language")
        .and_then(|v| v.as_object())
        .expect("files_by_language object");

    let cpp_count = by_lang.get("cpp").and_then(|v| v.as_u64()).unwrap_or(0);
    let js_count = by_lang
        .get("javascript")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    assert!(
        cpp_count >= 3,
        "expected cpp >= 3 in cpp-tinyxml2 (the 3 authored .cpp files); \
         got {cpp_count}; dist={dist:#?}"
    );
    assert_eq!(
        js_count, 0,
        "expected javascript = 0 in cpp-tinyxml2 (the 63 .js files all \
         live under doxygen-generated docs/, which the walker now skips \
         via the doxygen.css sentinel); got {js_count}; dist={dist:#?}"
    );
}
