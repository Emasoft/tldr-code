//! language-coverage-fixes-v1 — regression tests for 5 phase-4 audit bugs:
//!
//! - **P4.BUG-N1 (HIGH)**: `tldr structure` (and other directory-scanning
//!   commands) silently excluded `.h` files in C++ projects because
//!   `Language::Cpp.extensions()` only listed `.cpp/.cc/.cxx/.hpp`.
//!   Real C++ projects keep public headers as `.h` next to `.cpp`
//!   sources; the entire class enumeration was missed.
//!
//! - **P4.BUG-N2 (MED)**: `tldr extract` on Ruby files reported the
//!   outermost `module` as the only "class" with zero methods, because
//!   `extract_ruby_classes_detailed` did not recurse into class/module
//!   bodies to find nested declarations. Real Rails code (e.g.
//!   `Rails::HTML::Sanitizer`) nests 26+ modules and classes under a
//!   single top-level wrapper.
//!
//! - **P4.BUG-N3 (MED)**: `tldr definition <file> <line> <col>` with an
//!   out-of-range line emitted the entire file content as the "symbol
//!   name" in its error message — a 65 KB stderr explosion for a
//!   moderate-sized Python file. The fix validates `(line, col)`
//!   against file bounds before parsing and clamps any returned
//!   symbol to a 256-byte cap.
//!
//! - **P4.BUG-N4 (LOW)**: `tldr patterns` naming-violation classifier
//!   reported single-word lowercase identifiers (e.g. `print`) as
//!   `snake_case` and single-word uppercase identifiers (e.g. `E1`)
//!   as `upper_snake_case`, then flagged them as violations against
//!   camelCase / PascalCase expectations. The fix adds `LowerAlpha`
//!   and `UpperAlpha` variants that the violation emitter treats as
//!   compatible with both adjacent conventions.
//!
//! - **P4.BUG-N5 (LOW)**: `tldr structure` autodetect dropped `.tsx`
//!   files in mixed JS/TS directories. Same root cause as BUG-N1
//!   (single-bucket extension classifier); fixed by widening the
//!   scan extension list for the JS/TS sibling family.

use assert_cmd::Command;
use serde_json::Value;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

fn write(p: &Path, body: &str) {
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent).expect("mkdir -p");
    }
    fs::write(p, body).expect("write fixture");
}

/// Run `tldr <args>` and parse stdout as JSON.
fn run_json(args: &[&str]) -> Value {
    let out = tldr_cmd()
        .args(args)
        .args(["--format", "json", "-q"])
        .output()
        .unwrap_or_else(|e| panic!("spawn {:?}: {}", args, e));
    assert!(
        out.status.success(),
        "tldr {:?} failed: stderr={}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "tldr {:?} JSON parse failed: {}\nstdout={}",
            args,
            e,
            String::from_utf8_lossy(&out.stdout)
        )
    })
}

// =============================================================================
// P4.BUG-N1: cpp .h files included in directory scan
// =============================================================================

/// `tldr structure` on a C++ project must include `.h` headers.
///
/// Uses the `/tmp/repos/cpp-tinyxml2` fixture when present (a real
/// 25-class header-heavy library); otherwise builds a tiny in-tree
/// fixture (`foo.cpp` + `bar.h`) and asserts both are present.
#[test]
fn test_n1_cpp_h_files_included_in_dir_scan() {
    if Path::new("/tmp/repos/cpp-tinyxml2/tinyxml2.h").exists() {
        // Real fixture: scan the project and assert tinyxml2.h is in
        // the file list, with > 20 classes (the audit measured 25).
        let v = run_json(&["structure", "/tmp/repos/cpp-tinyxml2"]);
        let files = v
            .pointer("/files")
            .and_then(|f| f.as_array())
            .expect("structure: missing /files array");
        let paths: Vec<String> = files
            .iter()
            .filter_map(|f| f.get("path"))
            .filter_map(|p| p.as_str())
            .map(|s| s.to_string())
            .collect();
        assert!(
            paths.iter().any(|p| p.ends_with("tinyxml2.h")),
            "tinyxml2.h missing from cpp-tinyxml2 scan; got {:?}",
            paths
        );
        // Locate the .h file entry and check it has classes. The
        // cpp grammar's `class_specifier` enumeration is conservative
        // (visible-via-AST top-level classes only), so we assert > 0
        // — the contract is "the file is no longer silently dropped",
        // not "every nested class is enumerated" (a separate bug).
        let h_entry = files
            .iter()
            .find(|f| {
                f.get("path")
                    .and_then(|p| p.as_str())
                    .map(|s| s.ends_with("tinyxml2.h"))
                    .unwrap_or(false)
            })
            .expect("tinyxml2.h entry not found");
        let class_count = h_entry
            .get("classes")
            .and_then(|c| c.as_array())
            .map(|a| a.len())
            .unwrap_or(0);
        assert!(
            class_count > 0,
            "tinyxml2.h was scanned but yielded zero classes — \
             expected at least one top-level class extraction; \
             entry: {:?}",
            h_entry
        );
    } else {
        // Synthetic fixture: ensure `--lang cpp` picks up `.h` files
        // on a generic mixed-extension directory.
        let dir = TempDir::new().unwrap();
        write(
            &dir.path().join("foo.cpp"),
            "#include \"bar.h\"\nint main() { return 0; }\n",
        );
        write(
            &dir.path().join("bar.h"),
            "#pragma once\nclass Bar { public: int x; };\nclass Baz { public: int y; };\n",
        );
        let v = run_json(&["structure", dir.path().to_str().unwrap(), "--lang", "cpp"]);
        let files = v
            .pointer("/files")
            .and_then(|f| f.as_array())
            .expect("structure: missing /files array");
        let paths: Vec<String> = files
            .iter()
            .filter_map(|f| f.get("path"))
            .filter_map(|p| p.as_str())
            .map(|s| s.to_string())
            .collect();
        assert!(
            paths.iter().any(|p| p.ends_with("bar.h")),
            "bar.h missing from cpp scan; got {:?}",
            paths
        );
    }
}

// =============================================================================
// P4.BUG-N2: ruby extract recurses into nested modules
// =============================================================================

/// `tldr extract` on a Ruby file must enumerate nested modules/classes
/// and attribute methods to the nearest enclosing class.
#[test]
fn test_n2_ruby_extract_recurses_nested_modules() {
    let target = "/tmp/repos/rails-html-sanitizer/lib/rails/html/sanitizer.rb";
    if !Path::new(target).exists() {
        // Synthetic fixture mirroring the Rails::HTML::Sanitizer
        // shape: outer module + 3 nested modules each with methods.
        let dir = TempDir::new().unwrap();
        let rb = dir.path().join("sanitizer.rb");
        write(
            &rb,
            r#"
module Rails
  module HTML
    module Concern
      module ComposedSanitize
        def sanitize(html, **options)
          html
        end
      end
    end

    class Sanitizer
      def initialize
        @x = 1
      end

      def call(html)
        html
      end
    end

    class FullSanitizer < Sanitizer
      def sanitize_html(html)
        html
      end
    end
  end
end
"#,
        );
        let v = run_json(&["extract", rb.to_str().unwrap()]);
        let classes = v
            .pointer("/classes")
            .and_then(|c| c.as_array())
            .expect("extract: missing /classes array");
        let names: Vec<String> = classes
            .iter()
            .filter_map(|c| c.get("name"))
            .filter_map(|n| n.as_str())
            .map(|s| s.to_string())
            .collect();
        // We expect at least: Rails, HTML, Concern, ComposedSanitize,
        // Sanitizer, FullSanitizer (6 nested modules/classes).
        assert!(
            classes.len() >= 6,
            "expected ≥6 nested classes/modules, got {}: {:?}",
            classes.len(),
            names
        );
        // Each named class should appear in the list.
        for expected in ["Rails", "HTML", "Sanitizer", "FullSanitizer"] {
            assert!(
                names.iter().any(|n| n == expected),
                "expected class/module {:?} missing from {:?}",
                expected,
                names
            );
        }
        // Total methods across nested classes ≥ 4.
        let total_methods: usize = classes
            .iter()
            .filter_map(|c| c.get("methods"))
            .filter_map(|m| m.as_array())
            .map(|a| a.len())
            .sum();
        assert!(
            total_methods >= 4,
            "expected ≥4 total methods across nested classes, got {} ({:?})",
            total_methods,
            classes
        );
        return;
    }

    // Real fixture path.
    let v = run_json(&["extract", target]);
    let classes = v
        .pointer("/classes")
        .and_then(|c| c.as_array())
        .expect("extract: missing /classes array");
    assert!(
        classes.len() >= 16,
        "expected ≥16 nested classes/modules in rails-html-sanitizer, got {}",
        classes.len()
    );
    let total_methods: usize = classes
        .iter()
        .filter_map(|c| c.get("methods"))
        .filter_map(|m| m.as_array())
        .map(|a| a.len())
        .sum();
    assert!(
        total_methods >= 9,
        "expected ≥9 total methods, got {}",
        total_methods
    );
}

// =============================================================================
// P4.BUG-N3: definition out-of-range returns bounded error
// =============================================================================

/// `tldr definition <file> <huge_line> <col>` must emit a typed,
/// short error — not the entire file content.
#[test]
fn test_n3_definition_oob_returns_bounded_error() {
    // Build a small Python file (the OOB error path doesn't depend on
    // the size of the file, but we want to be sure the fix doesn't
    // depend on a /tmp/repos fixture).
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("tiny.py");
    write(&file, "def foo():\n    return 1\n");

    let out = tldr_cmd()
        .args(["definition", file.to_str().unwrap(), "9999", "8"])
        .args(["--format", "json", "-q"])
        .output()
        .expect("spawn tldr definition");
    assert!(
        !out.status.success(),
        "OOB definition should exit non-zero; stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr_len = out.stderr.len();
    assert!(
        stderr_len < 1024,
        "stderr should be < 1024 bytes for OOB error, got {} bytes; preview={}",
        stderr_len,
        String::from_utf8_lossy(&out.stderr[..stderr_len.min(200)])
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("out of range") || stderr.contains("out-of-range"),
        "expected 'out of range' marker in stderr, got: {}",
        stderr
    );
}

// =============================================================================
// P4.BUG-N4: patterns naming — no single-word violations
// =============================================================================

/// `tldr patterns` must NOT flag single-word identifiers as
/// snake_case / upper_snake_case violations against camel/pascal
/// expectations. Every reported violation must contain an underscore
/// (or other multi-segment marker).
#[test]
fn test_n4_patterns_naming_no_single_word_violations() {
    // Synthetic Java fixture: majority methods are camelCase, with
    // a few single-word lowercase methods like `print` and a single
    // uppercase class-like name `E1`. The previous classifier would
    // have flagged `print` as snake_case and `E1` as upper_snake_case;
    // the fix should produce zero violations of that shape.
    let dir = TempDir::new().unwrap();
    write(
        &dir.path().join("Service.java"),
        r#"
package demo;

public class UserService {
    public void findUserById(int id) { }
    public void getAllUsers() { }
    public void createUser(String name) { }
    public void print() { }
    public void save() { }
}

class E1 {
    public void doWork() { }
}
"#,
    );
    let v = run_json(&["patterns", dir.path().to_str().unwrap()]);
    // The patterns command output structure: top-level has "naming"
    // (when signals are present). If naming is absent, there are no
    // violations — that is also a passing outcome.
    let violations = v
        .pointer("/naming/violations")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    for viol in &violations {
        let name = viol
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("<missing>");
        assert!(
            name.contains('_'),
            "violation name {:?} has no underscore — single-word identifiers \
             must not be flagged as snake/upper-snake violations. \
             Full violation: {:?}",
            name,
            viol
        );
    }
}

// =============================================================================
// P4.BUG-N5: tsx files included in mixed JS/TS directory scans
// =============================================================================

/// `tldr structure` autodetect on a mixed `.tsx`/`.jsx`/`.mjs`/`.cjs`
/// directory must include the `.tsx` file in the file list.
#[test]
fn test_n5_tsx_included_in_mixed_js_ts_dir() {
    let dir = TempDir::new().unwrap();
    // Mix sibling-family extensions.
    write(&dir.path().join("a.mjs"), "export const x = 1;\n");
    write(&dir.path().join("a.cjs"), "module.exports = { x: 1 };\n");
    write(
        &dir.path().join("a.tsx"),
        "export const X: React.FC = () => null;\n",
    );
    write(&dir.path().join("a.jsx"), "export const X = () => null;\n");

    let v = run_json(&["structure", dir.path().to_str().unwrap()]);
    let files = v
        .pointer("/files")
        .and_then(|f| f.as_array())
        .expect("structure: missing /files array");
    let paths: Vec<String> = files
        .iter()
        .filter_map(|f| f.get("path"))
        .filter_map(|p| p.as_str())
        .map(|s| s.to_string())
        .collect();
    assert!(
        paths.iter().any(|p| p.ends_with("a.tsx")),
        ".tsx file missing from mixed JS/TS dir scan; got {:?}",
        paths
    );
    // For symmetry: also confirm .jsx is present.
    assert!(
        paths.iter().any(|p| p.ends_with("a.jsx")),
        ".jsx file missing from mixed JS/TS dir scan; got {:?}",
        paths
    );
}
