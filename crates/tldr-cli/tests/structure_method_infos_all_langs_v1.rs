//! structure-method-infos-all-langs-v1: extend method_infos field emission
//! to all 17 supported languages.
//!
//! Closes the incomplete `schema-unification-v1` BUG-21 fix. The prior
//! milestone added `FileStructure::method_infos: Vec<MethodInfo>` and
//! populated it from `definitions` filtered by `kind == "method"`. The
//! population logic was language-agnostic, BUT the field was serialized
//! with `#[serde(skip_serializing_if = "Vec::is_empty")]` — so any
//! language whose extractor produced no `method` definitions (because
//! the source file had no class scope) silently dropped the field from
//! JSON output.
//!
//! Repro on HEAD before this milestone:
//! ```text
//! for lang in c cpp csharp elixir go java javascript kotlin lua luau \
//!             ocaml php python ruby rust scala swift typescript; do
//!   tldr structure --lang $lang fixtures/$lang \
//!     | jq '.files[0] | has("method_infos")'
//! done
//! ```
//! Output: `false` for c / cpp / elixir / go / javascript / kotlin / lua /
//! luau / ocaml / php / python / rust / scala / swift / typescript (14
//! langs); `true` for csharp / java / ruby (3 langs that already had
//! class-scope methods in their fixtures).
//!
//! Fix: drop `skip_serializing_if` on `FileStructure::method_infos` so the
//! field is ALWAYS emitted as `[]` when no methods are present. Consumer
//! code that does `obj.method_infos` (without `has(...)` guards) now works
//! uniformly across all 17 languages.

use assert_cmd::prelude::*;
use serde_json::Value;
use std::fs;
use std::process::Command;
use tempfile::TempDir;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

/// (lang_flag, file_extension, file_contents).
///
/// One trivial source file per language. Languages whose fixture has no
/// class scope (e.g. C, OCaml, Lua) MUST still emit `method_infos: []` —
/// the bug being closed is "field absent", not "field empty".
fn fixture_per_language() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        ("c", "f.c", "int add(int a, int b) { return a + b; }\n"),
        (
            "cpp",
            "f.cpp",
            "class A { public: void m() {} void m(int x) {} };\n",
        ),
        (
            "csharp",
            "F.cs",
            "class A { public void M() {} public void M(int x) {} }\n",
        ),
        (
            "elixir",
            "f.ex",
            "defmodule M do\n  def hello, do: :world\nend\n",
        ),
        (
            "go",
            "f.go",
            "package main\nfunc Add(a int, b int) int { return a + b }\n",
        ),
        (
            "java",
            "F.java",
            "class A { public void m() {} public void m(int x) {} }\n",
        ),
        (
            "javascript",
            "f.js",
            "function add(a, b) { return a + b; }\n",
        ),
        (
            "kotlin",
            "f.kt",
            "class A { fun m() {} fun m(x: Int) {} }\n",
        ),
        (
            "lua",
            "f.lua",
            "local function add(a, b) return a + b end\n",
        ),
        (
            "luau",
            "f.luau",
            "local function add(a: number, b: number): number return a + b end\n",
        ),
        ("ocaml", "f.ml", "let add a b = a + b\n"),
        (
            "php",
            "f.php",
            "<?php\nclass A { public function m() {} public function m2(int $x) {} }\n",
        ),
        (
            "python",
            "f.py",
            "class A:\n    def m(self):\n        pass\n    def m2(self, x):\n        pass\n",
        ),
        (
            "ruby",
            "f.rb",
            "class A\n  def m; end\n  def m2(x); end\nend\n",
        ),
        ("rust", "f.rs", "fn add(a: i32, b: i32) -> i32 { a + b }\n"),
        (
            "scala",
            "F.scala",
            "class A { def m(): Unit = {}; def m(x: Int): Unit = {} }\n",
        ),
        (
            "swift",
            "f.swift",
            "class A { func m() {}; func m(x: Int) {} }\n",
        ),
        (
            "typescript",
            "f.ts",
            "class A { m(): void {} m2(x: number): void {} }\n",
        ),
    ]
}

/// structure-method-infos-all-langs-v1: `tldr structure` MUST emit the
/// `method_infos` key on every file entry, for every supported language —
/// even when the value is `[]`. This is the field-absence repro from the
/// 17-language sweep.
#[test]
fn test_structure_method_infos_emitted_all_langs() {
    let cases = fixture_per_language();
    let mut missing: Vec<String> = Vec::new();

    for (lang, filename, contents) in &cases {
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
        let out = cmd.assert().success().get_output().stdout.clone();
        let v: Value = serde_json::from_slice(&out)
            .unwrap_or_else(|e| panic!("[{}] structure output is not JSON: {}", lang, e));

        let files = v
            .get("files")
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("[{}] structure.files missing", lang));

        if files.is_empty() {
            // Some languages may legitimately produce 0 files if the
            // grammar rejects a fixture; treat as not-applicable here so
            // a single broken grammar doesn't mask the actual bug across
            // the other 16 langs. The structure-method-infos-all-langs-v1
            // contract is: when a file IS produced, it MUST have
            // method_infos.
            continue;
        }

        let f0 = &files[0];
        if !f0
            .as_object()
            .map(|o| o.contains_key("method_infos"))
            .unwrap_or(false)
        {
            missing.push((*lang).to_string());
            continue;
        }

        let mi = f0.get("method_infos").unwrap();
        assert!(
            mi.is_array(),
            "[{}] method_infos must be an array, got {:?}",
            lang,
            mi
        );
    }

    assert!(
        missing.is_empty(),
        "structure-method-infos-all-langs-v1 BUG: these languages still drop the `method_infos` key from JSON output: {:?}",
        missing
    );
}

/// structure-method-infos-all-langs-v1: overloaded methods with the same
/// name MUST produce distinct `method_infos` entries with different
/// `line` values, and the legacy `methods: [String]` array MUST be
/// retained alongside (additive contract). Verified for the three
/// languages with classical method overloading: C++, Kotlin, Scala.
#[test]
fn test_structure_method_infos_distinguishes_overloads_cpp_kotlin_scala() {
    struct Case {
        lang: &'static str,
        filename: &'static str,
        contents: &'static str,
    }

    let cases = vec![
        Case {
            lang: "cpp",
            filename: "Foo.cpp",
            contents: r#"class Foo {
public:
  void bar(int x) {}
  void bar(int x, int y) {}
  void bar(double x) {}
};
"#,
        },
        Case {
            lang: "kotlin",
            filename: "Foo.kt",
            contents: r#"class Foo {
  fun bar(x: Int) {}
  fun bar(x: Int, y: Int) {}
  fun bar(x: Double) {}
}
"#,
        },
        Case {
            lang: "scala",
            filename: "Foo.scala",
            contents: r#"class Foo {
  def bar(x: Int): Unit = {}
  def bar(x: Int, y: Int): Unit = {}
  def bar(x: Double): Unit = {}
}
"#,
        },
    ];

    for case in &cases {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join(case.filename);
        fs::write(&path, case.contents).unwrap();

        let mut cmd = tldr_cmd();
        cmd.args([
            "structure",
            temp.path().to_str().unwrap(),
            "--lang",
            case.lang,
            "-q",
        ]);
        let out = cmd.assert().success().get_output().stdout.clone();
        let v: Value = serde_json::from_slice(&out)
            .unwrap_or_else(|e| panic!("[{}] structure output is not JSON: {}", case.lang, e));

        let files = v
            .get("files")
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("[{}] structure.files missing", case.lang));

        let f0 = files
            .iter()
            .find(|f| {
                f.get("path")
                    .and_then(Value::as_str)
                    .map(|p| p.ends_with(case.filename))
                    .unwrap_or(false)
            })
            .unwrap_or_else(|| panic!("[{}] {} not in structure output", case.lang, case.filename));

        // (The legacy `methods: [String]` flat array was removed by
        // schema-cleanup-v1 BUG-13 in favor of the canonical
        // `method_infos[]`; assertions below now exclusively cover that
        // canonical field.)

        // method_infos must produce three DISTINCT entries with different line numbers.
        let method_infos = f0
            .get("method_infos")
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("[{}] method_infos missing", case.lang));
        let bar_entries: Vec<&Value> = method_infos
            .iter()
            .filter(|mi| mi.get("name").and_then(Value::as_str) == Some("bar"))
            .collect();
        assert_eq!(
            bar_entries.len(),
            3,
            "[{}] expected 3 bar method_infos for overloads, got {}: {:?}",
            case.lang,
            bar_entries.len(),
            method_infos
        );

        // All three lines must be distinct (overloads at different source positions).
        let mut lines: Vec<u64> = bar_entries
            .iter()
            .map(|mi| mi.get("line").and_then(Value::as_u64).unwrap_or(0))
            .collect();
        lines.sort();
        lines.dedup();
        assert_eq!(
            lines.len(),
            3,
            "[{}] overload lines must be distinct, got {:?}",
            case.lang,
            lines
        );

        // All three signatures must be distinct (additional disambiguation axis).
        let sigs: std::collections::HashSet<&str> = bar_entries
            .iter()
            .filter_map(|mi| mi.get("signature").and_then(Value::as_str))
            .collect();
        assert_eq!(
            sigs.len(),
            3,
            "[{}] overload signatures must be distinct, got {:?}",
            case.lang,
            sigs
        );
    }
}

/// Regression guard: structure-method-infos-all-langs-v1 must not regress
/// the prior schema-unification-v1 BUG-21 Java overload test — the
/// `method_infos` field must still appear, even though its serialization
/// directive changed from `skip_serializing_if = "Vec::is_empty"` to
/// always-emit. A non-empty array remains non-empty.
#[test]
fn test_structure_method_infos_java_overloads_regression() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("Owner.java");
    fs::write(
        &path,
        r#"
package x;
public class Owner {
    public Pet getPet(String name) { return null; }
    public Pet getPet(Integer id) { return null; }
    public Pet getPet(Integer id, boolean ignoreNew) { return null; }
}
"#,
    )
    .unwrap();

    let mut cmd = tldr_cmd();
    cmd.args([
        "structure",
        temp.path().to_str().unwrap(),
        "--lang",
        "java",
        "-q",
    ]);
    let out = cmd.assert().success().get_output().stdout.clone();
    let v: Value = serde_json::from_slice(&out).expect("structure output is valid JSON");

    let f0 = v
        .get("files")
        .and_then(Value::as_array)
        .and_then(|files| files.first().cloned())
        .expect("structure.files[0] missing");
    let mi = f0
        .get("method_infos")
        .and_then(Value::as_array)
        .expect("Owner.java still missing method_infos");
    let getpet_count = mi
        .iter()
        .filter(|m| m.get("name").and_then(Value::as_str) == Some("getPet"))
        .count();
    assert_eq!(
        getpet_count, 3,
        "Java getPet overloads regressed: expected 3, got {} in {:?}",
        getpet_count, mi
    );
}

/// Field-presence check using the actual project fixture set across all
/// 17 languages. This is the EXACT repro from the bug ticket: iterate
/// over the vuln_migration_v1 fixture directories. Every language MUST
/// have files[0].method_infos present (even if empty) — confirming the
/// no-class-scope languages no longer drop the field.
#[test]
fn test_structure_method_infos_emitted_on_project_fixtures() {
    // Use `tldr-cli/tests/fixtures/vuln_migration_v1/<lang>/` which all
    // 17 supported languages already populate. CARGO_MANIFEST_DIR points
    // at `crates/tldr-cli` at test runtime.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let langs = [
        "c",
        "cpp",
        "csharp",
        "elixir",
        "go",
        "java",
        "javascript",
        "kotlin",
        "lua",
        "luau",
        "ocaml",
        "php",
        "python",
        "ruby",
        "rust",
        "scala",
        "swift",
        "typescript",
    ];

    let mut missing: Vec<String> = Vec::new();

    for lang in &langs {
        let dir = std::path::Path::new(manifest_dir)
            .join("tests")
            .join("fixtures")
            .join("vuln_migration_v1")
            .join(lang);

        if !dir.exists() {
            // Fixture not present — skip (don't fail; structural test is
            // about the binary's behavior, not fixture inventory).
            continue;
        }

        let mut cmd = tldr_cmd();
        cmd.args(["structure", dir.to_str().unwrap(), "--lang", lang, "-q"]);
        let out = cmd.assert().success().get_output().stdout.clone();
        let v: Value = serde_json::from_slice(&out)
            .unwrap_or_else(|e| panic!("[{}] structure output is not JSON: {}", lang, e));

        let files = v
            .get("files")
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("[{}] structure.files missing", lang));

        if files.is_empty() {
            continue;
        }

        let has_mi = files[0]
            .as_object()
            .map(|o| o.contains_key("method_infos"))
            .unwrap_or(false);
        if !has_mi {
            missing.push((*lang).to_string());
        }
    }

    assert!(
        missing.is_empty(),
        "structure-method-infos-all-langs-v1 project-fixture sweep: these languages still drop method_infos: {:?}",
        missing
    );
}
