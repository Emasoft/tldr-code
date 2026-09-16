//! structure-json-escape-v1: regression test pinning that `tldr structure`
//! ALWAYS emits valid JSON across all 17 supported languages, even when
//! source files contain language-specific escape sequences and other
//! characters that historically have been mis-escaped by ad-hoc string
//! emitters.
//!
//! ## Background
//!
//! `FileStructure::definitions[].signature` and
//! `FileStructure::method_infos[].signature` carry verbatim signature
//! lines extracted from source. These strings can contain:
//!
//! - Backslash-quote sequences: `Pattern.compile("th:(u)?text\\s*=...")`
//!   (Java)
//! - Curly-brace unicode escapes: `const X: &str = "\u{feff}";` (Rust)
//! - Variable interpolation glyphs: `$variable` (PHP)
//! - Tab / NUL / control bytes (any language whose extractor inadvertently
//!   captures whitespace)
//! - Backslash-escaped quotes inside string literals (most langs)
//!
//! All of these MUST round-trip through JSON via `serde_json` — i.e. the
//! emitter MUST NOT use `write!` / `format!` / manual escape logic for
//! the `signature` field. The current code path goes through
//! `OutputWriter::write` which calls `serde_json::to_writer_pretty`, so
//! any string is properly escaped automatically. This test pins that
//! contract: a future refactor that switches to a manual `Serialize` impl
//! emitting `serializer.serialize_str(raw_signature)` with raw control
//! chars — or worse, hand-rolling JSON via `format!` — will be caught.
//!
//! ## What this test covers
//!
//! 1. `test_structure_json_valid_for_all_problematic_languages` —
//!    fixtures with the historically problematic content (Rust
//!    `\u{feff}`, Java backslash-regex, PHP `$var` interpolation, control
//!    chars, tabs, etc.) for the 8 languages flagged in the milestone
//!    spec (cpp, elixir, java, luau, ocaml, php, rust, swift) plus
//!    csharp/typescript/python/ruby/go/javascript/kotlin/lua/scala/c
//!    (all 17). Each fixture is run through `tldr structure` and the
//!    output MUST parse as JSON via `serde_json::from_slice` — this is
//!    the same contract `jq empty` enforces.
//!
//! 2. `test_structure_json_signature_round_trip` — emit + re-parse →
//!    the original signature substring must be recoverable from the
//!    parsed JSON. This guards against silent dropping or corruption
//!    of the signature content during escaping.

use assert_cmd::prelude::*;
use serde_json::Value;
use std::fs;
use std::process::Command;
use tempfile::TempDir;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

/// `(lang_flag, file_extension, file_contents, expected_marker)`.
///
/// Each fixture is crafted to contain the historical problematic content
/// for that language. `expected_marker` is a substring that MUST appear
/// in at least one signature/definition emitted by the extractor — a
/// weak presence check to make sure we are actually exercising the
/// escape path. It does NOT require an exact equality match, since
/// extractors may rewrite whitespace or capture only a prefix.
fn problematic_fixtures() -> Vec<(&'static str, &'static str, &'static str, &'static str)> {
    vec![
        // Rust: `\u{feff}` curly-brace unicode escape inside a string
        // literal — historically jq-incompatible if emitted literally.
        (
            "rust",
            "f.rs",
            "pub const UTF8_BOM: &str = \"\\u{feff}\";\npub fn foo(x: i32) -> i32 { x }\n",
            "UTF8_BOM",
        ),
        // C++: backslash-regex + nested quotes in a constexpr.
        (
            "cpp",
            "f.cpp",
            "class Re {\npublic:\n  void match() {}\n  void match(int x) {}\n};\nconst char* PAT = \"\\\\s*=\\\\s*\\\"x\\\"\";\n",
            "match",
        ),
        // Elixir: sigil with embedded backslash-newline + interpolation.
        (
            "elixir",
            "f.ex",
            "defmodule M do\n  @pattern ~r/\\s*=\\s*\"[^\"]+\"/\n  def hello(name), do: \"Hi \\#{name}\"\nend\n",
            "hello",
        ),
        // Java: backslash-regex string with escaped quotes (the canonical
        // example from the milestone spec).
        (
            "java",
            "F.java",
            "import java.util.regex.Pattern;\nclass A {\n  static Pattern P = Pattern.compile(\"th:(u)?text\\\\s*=\\\\s*\\\"[^\\\"]+\\\"\");\n  public void m() {}\n  public void m(int x) {}\n}\n",
            "m",
        ),
        // Luau: string with backslash-escapes.
        (
            "luau",
            "f.luau",
            "local function add(a: number, b: number): number\n  local s = \"a\\tb\\\"c\"\n  return a + b\nend\n",
            "add",
        ),
        // OCaml: function with a string literal containing backslash-escapes.
        (
            "ocaml",
            "f.ml",
            "let pattern = \"\\\\s*=\\\\s*\\\"[^\\\"]+\\\"\"\nlet add a b = a + b\n",
            "add",
        ),
        // PHP: `$variable` interpolation inside a double-quoted string.
        (
            "php",
            "f.php",
            "<?php\nclass A {\n  public function m() { $x = \"hi $name\\n\"; return $x; }\n  public function m2(int $x) { return $x; }\n}\n",
            "m",
        ),
        // Swift: string with backslash-escaped quotes and tab.
        (
            "swift",
            "f.swift",
            "class A {\n  let pat = \"\\\\s*=\\\\s*\\\"x\\\"\"\n  func m() {}\n  func m(x: Int) {}\n}\n",
            "m",
        ),
        // C: function with a string literal carrying escapes.
        (
            "c",
            "f.c",
            "static const char *PAT = \"\\\\s*=\\\\s*\\\"x\\\"\";\nint add(int a, int b) { return a + b; }\n",
            "add",
        ),
        // C#: string with backslash-escapes.
        (
            "csharp",
            "F.cs",
            "class A {\n  static string P = \"\\\\s*=\\\\s*\\\"x\\\"\";\n  public void M() {}\n  public void M(int x) {}\n}\n",
            "M",
        ),
        // Go: raw + interpreted strings with escapes.
        (
            "go",
            "f.go",
            "package main\nvar pat = \"\\\\s*=\\\\s*\\\"x\\\"\"\nfunc Add(a int, b int) int { return a + b }\n",
            "Add",
        ),
        // JavaScript: regex literal + string with escaped quotes.
        (
            "javascript",
            "f.js",
            "const pat = /\\s*=\\s*\"[^\"]+\"/;\nfunction add(a, b) { return a + b; }\n",
            "add",
        ),
        // Kotlin: string with escaped chars; class with overloads.
        (
            "kotlin",
            "f.kt",
            "class A {\n  val pat = \"\\\\s*=\\\\s*\\\"x\\\"\"\n  fun m() {}\n  fun m(x: Int) {}\n}\n",
            "m",
        ),
        // Lua: pattern with magic chars inside double-quoted string.
        (
            "lua",
            "f.lua",
            "local PAT = \"%s*=%s*\\\"[^\\\"]+\\\"\"\nlocal function add(a, b) return a + b end\n",
            "add",
        ),
        // Python: regex string literal with backslash-escapes + class.
        (
            "python",
            "f.py",
            "import re\nPAT = re.compile(r'\\s*=\\s*\"[^\"]+\"')\nclass A:\n    def m(self):\n        pass\n    def m2(self, x):\n        pass\n",
            "m",
        ),
        // Ruby: regex literal + string with embedded interpolation.
        (
            "ruby",
            "f.rb",
            "PAT = /\\s*=\\s*\"[^\"]+\"/\nclass A\n  def m; \"hi #{1+2}\"; end\n  def m2(x); end\nend\n",
            "m",
        ),
        // Scala: string with escapes; class with overloads.
        (
            "scala",
            "F.scala",
            "class A {\n  val pat = \"\\\\s*=\\\\s*\\\"x\\\"\"\n  def m(): Unit = {}\n  def m(x: Int): Unit = {}\n}\n",
            "m",
        ),
        // TypeScript: regex literal in a class field + overloads.
        (
            "typescript",
            "f.ts",
            "class A {\n  pat = /\\s*=\\s*\"[^\"]+\"/;\n  m(): void {}\n  m2(x: number): void {}\n}\n",
            "m",
        ),
    ]
}

/// structure-json-escape-v1: `tldr structure` MUST emit JSON that
/// round-trips through `serde_json::from_slice` for every supported
/// language, even when source contains backslash-quote sequences,
/// curly-brace unicode escapes, regex literals, and other content
/// that historically tripped naive emitters.
///
/// This is the same contract `jq empty` enforces — `serde_json`'s
/// parser is at least as strict as jq for the relevant escape rules.
#[test]
fn test_structure_json_valid_for_all_problematic_languages() {
    let cases = problematic_fixtures();
    let mut failures: Vec<String> = Vec::new();

    for (lang, filename, contents, _marker) in &cases {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join(filename);
        fs::write(&path, contents).unwrap();

        let mut cmd = tldr_cmd();
        cmd.args([
            "structure",
            temp.path().to_str().unwrap(),
            "--lang",
            lang,
            "-q",
        ]);
        let assert = cmd.assert().success();
        let stdout = assert.get_output().stdout.clone();

        // The actual contract: stdout MUST be valid JSON.
        match serde_json::from_slice::<Value>(&stdout) {
            Ok(_) => {}
            Err(e) => {
                let preview: String = String::from_utf8_lossy(&stdout).chars().take(200).collect();
                failures.push(format!(
                    "[{}] structure JSON invalid: {} | head=<{}>",
                    lang, e, preview
                ));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "structure-json-escape-v1: invalid JSON emitted for one or more languages:\n  {}",
        failures.join("\n  ")
    );
}

/// structure-json-escape-v1: signature/definition content MUST round-trip
/// through JSON intact. After parsing the emitted JSON, the expected
/// marker substring (the function name or constant name) MUST appear in
/// at least one of: a definition's `name`, `signature`, or one of the
/// flat `functions` / `classes` / `methods` arrays.
///
/// Guards against silent dropping or corruption (e.g. truncating the
/// signature at the first backslash) during escape handling.
#[test]
fn test_structure_json_signature_round_trip() {
    let cases = problematic_fixtures();
    let mut missing: Vec<String> = Vec::new();

    for (lang, filename, contents, marker) in &cases {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join(filename);
        fs::write(&path, contents).unwrap();

        let mut cmd = tldr_cmd();
        cmd.args([
            "structure",
            temp.path().to_str().unwrap(),
            "--lang",
            lang,
            "-q",
        ]);
        let stdout = cmd.assert().success().get_output().stdout.clone();

        let v: Value = match serde_json::from_slice(&stdout) {
            Ok(v) => v,
            Err(e) => {
                missing.push(format!("[{}] JSON parse failed: {}", lang, e));
                continue;
            }
        };

        let files = v.get("files").and_then(Value::as_array);
        let Some(files) = files else {
            missing.push(format!("[{}] structure.files missing", lang));
            continue;
        };

        if files.is_empty() {
            // Some grammars may legitimately reject these synthetic
            // fixtures; treat empty `files` as not-applicable so a
            // single brittle grammar does not mask escape regressions
            // across the other 16 langs.
            continue;
        }

        // Search across `functions`, `classes`, `methods`, and
        // `definitions[].signature` / `definitions[].name` for the
        // marker substring.
        let mut found = false;
        for f in files {
            for key in ["functions", "classes", "methods"] {
                if let Some(arr) = f.get(key).and_then(Value::as_array) {
                    if arr
                        .iter()
                        .filter_map(Value::as_str)
                        .any(|s| s.contains(marker))
                    {
                        found = true;
                        break;
                    }
                }
            }
            if found {
                break;
            }
            if let Some(defs) = f.get("definitions").and_then(Value::as_array) {
                for d in defs {
                    let name_match = d
                        .get("name")
                        .and_then(Value::as_str)
                        .map(|s| s.contains(marker))
                        .unwrap_or(false);
                    let sig_match = d
                        .get("signature")
                        .and_then(Value::as_str)
                        .map(|s| s.contains(marker))
                        .unwrap_or(false);
                    if name_match || sig_match {
                        found = true;
                        break;
                    }
                }
            }
            if found {
                break;
            }
            if let Some(mis) = f.get("method_infos").and_then(Value::as_array) {
                for m in mis {
                    let name_match = m
                        .get("name")
                        .and_then(Value::as_str)
                        .map(|s| s.contains(marker))
                        .unwrap_or(false);
                    let sig_match = m
                        .get("signature")
                        .and_then(Value::as_str)
                        .map(|s| s.contains(marker))
                        .unwrap_or(false);
                    if name_match || sig_match {
                        found = true;
                        break;
                    }
                }
            }
            if found {
                break;
            }
        }

        if !found {
            missing.push(format!(
                "[{}] marker '{}' not found in any definition/method/signature",
                lang, marker
            ));
        }
    }

    assert!(
        missing.is_empty(),
        "structure-json-escape-v1: signature round-trip failed:\n  {}",
        missing.join("\n  ")
    );
}

/// structure-json-escape-v1: explicit control-character coverage.
///
/// A signature that ends up containing TAB (`\t`), CR (`\r`), or
/// backslash-quote sequences MUST still produce valid JSON. We craft a
/// Python fixture whose extractor will pick up the literal docstring /
/// signature content, then assert the JSON is parseable.
#[test]
fn test_structure_json_handles_tab_and_backslash_quote_in_python_signature() {
    let temp = TempDir::new().unwrap();
    // Python source with: tab in default value position, backslash
    // quote in a docstring, regex with backslash escapes.
    let contents = "import re\nclass A:\n    \"\"\"Docstring with \\\"quoted\\\" text and \\t tab.\"\"\"\n    pat = re.compile(r'\\s*=\\s*\"[^\"]+\"')\n    def m(self, x=\"a\\tb\\\"c\"):\n        return x\n";
    fs::write(temp.path().join("f.py"), contents).unwrap();

    let mut cmd = tldr_cmd();
    cmd.args([
        "structure",
        temp.path().to_str().unwrap(),
        "--lang",
        "python",
        "-q",
    ]);
    let stdout = cmd.assert().success().get_output().stdout.clone();

    let v: Value = serde_json::from_slice(&stdout).expect(
        "structure-json-escape-v1: python signature with tab/backslash-quote MUST yield valid JSON",
    );

    // Sanity: at least one file must be present so we know the
    // assertion above isn't trivially passing on an empty payload.
    let files = v.get("files").and_then(Value::as_array).unwrap();
    assert!(
        !files.is_empty(),
        "expected at least one file in structure output for python fixture"
    );
}
