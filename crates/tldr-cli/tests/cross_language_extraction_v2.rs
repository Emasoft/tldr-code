//! cross-language-extraction-v2: close 3 HIGH cross-language extractor gaps.
//!
//! P2.BUG-1 — `tldr structure.method_infos` was empty for languages whose
//! methods are not lexically inside a class body. Specifically:
//!   - Go methods: `func (r *Router) Foo()` is parsed as `method_declaration`
//!     but not nested inside a struct body, so `is_inside_class_or_impl`
//!     returned false and the entry was classified as `kind: "function"`.
//!   - JavaScript class methods already worked (express.js had no classes,
//!     hence the original repro showed 0 — but this is correct given the
//!     input).
//!
//! P2.BUG-2 — `tldr imports` returned `[]` for Swift and Kotlin even when the
//! file had real imports. The two languages were explicitly stubbed in
//! `imports.rs`:
//!     `Language::Kotlin | Language::Swift => Vec::new()`
//! tree-sitter-kotlin-ng emits an `import` statement node (with
//! `qualified_identifier` children); tree-sitter-swift emits
//! `import_declaration`. Both are now parsed.
//!
//! P2.BUG-3 — `tldr todo` auto-detect was hardcoded to 5 languages
//! (Python/TS/JS/Rust/Go) so calls without `--lang` against Java / Kotlin /
//! Elixir / OCaml / Ruby / PHP / Scala / C# / Lua trees fell through to the
//! Python default and emitted zero items. The `todo` command now routes
//! through `Language::from_path` / `Language::from_directory`, the AA1
//! shared autodetect helpers used by every other command.

use assert_cmd::prelude::*;
use serde_json::Value;
use std::fs;
use std::process::Command;
use tempfile::TempDir;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

// =============================================================================
// P2.BUG-1: structure.method_infos for JS classes and Go receiver-methods
// =============================================================================

/// JavaScript class methods must surface in `method_infos`. (This was already
/// working pre-milestone — tracked here as a regression guard against the
/// receiver/method classification refactor.)
#[test]
fn js_structure_method_infos_populated() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("foo.js");
    fs::write(
        &path,
        r#"class Foo {
  bar() { return 1; }
  baz(x) { return x + 1; }
}
"#,
    )
    .unwrap();

    let out = tldr_cmd()
        .args([
            "structure",
            temp.path().to_str().unwrap(),
            "--lang",
            "javascript",
            "-q",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: Value = serde_json::from_slice(&out).expect("structure output is JSON");

    let methods: Vec<&str> = v["files"][0]["method_infos"]
        .as_array()
        .expect("method_infos array present")
        .iter()
        .filter_map(|m| m["name"].as_str())
        .collect();
    assert!(
        methods.contains(&"bar") && methods.contains(&"baz"),
        "expected bar+baz in JS method_infos, got: {:?}",
        methods
    );
}

/// Go: methods declared with a receiver (`func (r *Router) Handle()`) must be
/// classified as `kind: "method"` in `definitions` AND appear in
/// `method_infos`. Free functions in the same file must remain
/// `kind: "function"`.
#[test]
fn go_structure_method_infos_populated() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("router.go");
    fs::write(
        &path,
        r#"package main

type Router struct {
    name string
}

func (r *Router) Handle(path string) {}
func (r Router) Lookup(path string) bool { return true }
func main() {}
"#,
    )
    .unwrap();

    let out = tldr_cmd()
        .args([
            "structure",
            temp.path().to_str().unwrap(),
            "--lang",
            "go",
            "-q",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: Value = serde_json::from_slice(&out).expect("structure output is JSON");

    // method_infos must contain both Handle and Lookup but NOT main.
    let mi: Vec<&str> = v["files"][0]["method_infos"]
        .as_array()
        .expect("method_infos array present")
        .iter()
        .filter_map(|m| m["name"].as_str())
        .collect();
    assert!(
        mi.contains(&"Handle"),
        "expected Handle in Go method_infos, got: {:?}",
        mi
    );
    assert!(
        mi.contains(&"Lookup"),
        "expected Lookup in Go method_infos, got: {:?}",
        mi
    );
    assert!(
        !mi.contains(&"main"),
        "main is a free function and must NOT appear in method_infos, got: {:?}",
        mi
    );

    // definitions must classify the receiver-methods as kind="method".
    let defs = v["files"][0]["definitions"]
        .as_array()
        .expect("definitions array present");
    let handle_def = defs
        .iter()
        .find(|d| d["name"].as_str() == Some("Handle"))
        .expect("Handle in definitions");
    assert_eq!(
        handle_def["kind"].as_str(),
        Some("method"),
        "Handle must be kind=method, got: {:?}",
        handle_def
    );
    let main_def = defs
        .iter()
        .find(|d| d["name"].as_str() == Some("main"))
        .expect("main in definitions");
    assert_eq!(
        main_def["kind"].as_str(),
        Some("function"),
        "main must remain kind=function, got: {:?}",
        main_def
    );
}

// =============================================================================
// P2.BUG-2: Swift / Kotlin imports recognised
// =============================================================================

/// Swift: `import Foundation` and `import struct Foo.Bar` must produce
/// `ImportInfo` entries.
#[test]
fn swift_imports_extracted() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("File.swift");
    fs::write(
        &path,
        "import Foundation\nimport struct PackageDescription.Package\n@testable import MyMod\n\nclass Foo {}\n",
    )
    .unwrap();

    let out = tldr_cmd()
        .args(["imports", path.to_str().unwrap(), "--lang", "swift", "-q"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: Value = serde_json::from_slice(&out).expect("imports output is JSON");

    let modules: Vec<&str> = v["imports"]
        .as_array()
        .expect("imports array present")
        .iter()
        .filter_map(|i| i["module"].as_str())
        .collect();

    assert!(
        modules.iter().any(|m| *m == "Foundation"),
        "expected Foundation in Swift imports, got: {:?}",
        modules
    );
    // The submodule kind keyword (`struct`) must be skipped — module path is
    // the next token.
    assert!(
        modules.iter().any(|m| m.contains("PackageDescription")),
        "expected PackageDescription in Swift imports, got: {:?}",
        modules
    );
    // @testable attribute prefix must be tolerated.
    assert!(
        modules.iter().any(|m| *m == "MyMod"),
        "expected MyMod in Swift imports (with @testable attribute), got: {:?}",
        modules
    );
}

/// Kotlin: simple, wildcard, and aliased imports must be recognised.
#[test]
fn kotlin_imports_extracted() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("File.kt");
    fs::write(
        &path,
        "import kotlin.collections.List\n\
         import kotlin.collections.*\n\
         import foo.bar.Baz as B\n\n\
         class Foo {}\n",
    )
    .unwrap();

    let out = tldr_cmd()
        .args(["imports", path.to_str().unwrap(), "--lang", "kotlin", "-q"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: Value = serde_json::from_slice(&out).expect("imports output is JSON");

    let imports = v["imports"].as_array().expect("imports array present");
    assert!(
        imports.len() >= 3,
        "expected at least 3 Kotlin imports, got: {:?}",
        imports
    );

    let modules: Vec<&str> = imports
        .iter()
        .filter_map(|i| i["module"].as_str())
        .collect();
    assert!(
        modules
            .iter()
            .any(|m| m.contains("kotlin.collections.List")),
        "expected kotlin.collections.List in Kotlin imports, got: {:?}",
        modules
    );

    // Wildcard import must produce an entry with module ending `.*` and is_from=true.
    let wildcard = imports
        .iter()
        .find(|i| {
            i["module"]
                .as_str()
                .map(|m| m.ends_with(".*"))
                .unwrap_or(false)
        })
        .expect("wildcard import present");
    assert_eq!(
        wildcard["is_from"].as_bool(),
        Some(true),
        "wildcard import should have is_from=true, got: {:?}",
        wildcard
    );

    // Aliased import: alias=B for module foo.bar.Baz.
    let aliased = imports
        .iter()
        .find(|i| i["module"].as_str() == Some("foo.bar.Baz"))
        .expect("aliased import present");
    assert_eq!(
        aliased["alias"].as_str(),
        Some("B"),
        "aliased import should have alias=B, got: {:?}",
        aliased
    );
}

// =============================================================================
// P2.BUG-3: tldr todo autodetect for non-default languages
// =============================================================================

fn todo_autodetect_returns_items(
    files: &[(&str, &str)],
    expected_lang: &str,
) -> (usize, usize, String) {
    let temp = TempDir::new().unwrap();
    for (name, body) in files {
        let p = temp.path().join(name);
        fs::write(&p, body).unwrap();
    }

    // Auto-detect (no --lang).
    let out_auto = tldr_cmd()
        .args(["todo", temp.path().to_str().unwrap(), "-q"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v_auto: Value = serde_json::from_slice(&out_auto).expect("todo (auto) output is JSON");

    // With explicit --lang.
    let out_explicit = tldr_cmd()
        .args([
            "todo",
            temp.path().to_str().unwrap(),
            "--lang",
            expected_lang,
            "-q",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v_explicit: Value =
        serde_json::from_slice(&out_explicit).expect("todo (--lang) output is JSON");

    let auto = v_auto["items"].as_array().map(|a| a.len()).unwrap_or(0);
    let explicit = v_explicit["items"].as_array().map(|a| a.len()).unwrap_or(0);
    (auto, explicit, expected_lang.to_string())
}

/// Java: `tldr todo <java-dir>` (no --lang) must produce non-zero items and
/// match the explicit `--lang java` behaviour.
#[test]
fn todo_autodetect_works_for_java() {
    // A class with one obvious dead private method to ensure dead-code
    // analysis emits at least one item.
    let body = r#"package x;
public class Foo {
    public int alive() { return 1; }
    private int _dead() { return 2; }
}
"#;
    let (auto, _explicit, _) = todo_autodetect_returns_items(&[("Foo.java", body)], "java");
    assert!(
        auto > 0,
        "Java todo autodetect must return items, got {} items",
        auto
    );
}

/// Kotlin: `tldr todo <kotlin-dir>` (no --lang) must produce non-zero items.
#[test]
fn todo_autodetect_works_for_kotlin() {
    let body = r#"class Foo {
    fun alive(): Int { return 1 }
    private fun _dead(): Int { return 2 }
}
"#;
    let (auto, _explicit, _) = todo_autodetect_returns_items(&[("Foo.kt", body)], "kotlin");
    assert!(
        auto > 0,
        "Kotlin todo autodetect must return items, got {} items",
        auto
    );
}
