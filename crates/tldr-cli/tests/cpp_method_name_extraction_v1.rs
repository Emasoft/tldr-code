//! cpp-method-name-extraction-v1: regression coverage for the cpp method
//! name extraction bug.
//!
//! Background: tree-sitter-cpp 0.23.x emits `field_identifier` (NOT
//! `identifier`) as the leaf declarator inside a `function_declarator` for
//! class-body inline method definitions. The pre-fix
//! `extract_name_from_function_declarator` in
//! `crates/tldr-core/src/ast/extract.rs` only matched `identifier` /
//! `pointer_declarator` / `qualified_identifier` / `destructor_name`,
//! returning `None` for `field_identifier` and producing empty strings in
//! the legacy `methods: [String]` output of `tldr structure`.
//!
//! The companion `method_infos: [{name,line}]` view took a different code
//! path (via `definitions`) that DID handle `field_identifier`, so
//! `method_infos` showed correct names while `methods` showed `["", "", ""]`
//! — a confusing inconsistency for JSON consumers.
//!
//! This test file pins both the inline-method and out-of-class-definition
//! shapes so the fix cannot regress.

use assert_cmd::prelude::*;
use serde_json::Value;
use std::fs;
use std::process::Command;
use tempfile::TempDir;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

/// Three overloads of `bar` defined inline inside a class body. All three
/// must appear in `methods` as `"bar"` (not `""`) and produce three distinct
/// `method_infos` entries differing only in `line`.
#[test]
fn test_cpp_overload_method_names_extracted() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("Foo.cpp");
    fs::write(
        &path,
        r#"class Foo {
  void bar() {}
  int bar(int x) { return x; }
  double bar(double x, double y) { return x + y; }
};
"#,
    )
    .unwrap();

    let mut cmd = tldr_cmd();
    cmd.args([
        "structure",
        temp.path().to_str().unwrap(),
        "--lang",
        "cpp",
        "-q",
    ]);
    let out = cmd.assert().success().get_output().stdout.clone();
    let v: Value = serde_json::from_slice(&out).expect("structure output is not valid JSON");

    let files = v
        .get("files")
        .and_then(Value::as_array)
        .expect("structure.files missing");
    let f0 = files
        .iter()
        .find(|f| {
            f.get("path")
                .and_then(Value::as_str)
                .map(|p| p.ends_with("Foo.cpp"))
                .unwrap_or(false)
        })
        .expect("Foo.cpp not in structure output");

    // 1) `method_infos` MUST have 3 entries, all named "bar", with three
    //    DISTINCT `line` values.
    // (The legacy flat `methods: [String]` array was removed by
    // schema-cleanup-v1 BUG-13 in favor of the canonical `method_infos[]`.)
    let method_infos = f0
        .get("method_infos")
        .and_then(Value::as_array)
        .expect("method_infos missing");
    assert_eq!(
        method_infos.len(),
        3,
        "expected 3 method_infos entries, got {}",
        method_infos.len()
    );
    for mi in method_infos {
        let n = mi.get("name").and_then(Value::as_str).unwrap_or("");
        assert_eq!(n, "bar", "method_infos entry has wrong name: {mi:?}");
    }
    let mut lines: Vec<i64> = method_infos
        .iter()
        .filter_map(|mi| mi.get("line").and_then(Value::as_i64))
        .collect();
    lines.sort();
    lines.dedup();
    assert_eq!(lines.len(), 3, "expected 3 distinct lines, got {lines:?}");
}

/// Out-of-class definition: `void Foo::bar() {}`. The cpp grammar produces
/// `function_declarator(declarator: qualified_identifier(scope, name))`. We
/// return the unqualified `name` (here "bar") so this entry collates with
/// the inline form (and so the legacy `methods: [String]` view shows "bar"
/// instead of "Foo::bar"). This decision is documented inline at the
/// `qualified_identifier` arm of `extract_name_from_declarator_inner`.
#[test]
fn test_cpp_qualified_method_name() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("Foo.cpp");
    fs::write(
        &path,
        r#"class Foo {
public:
  void bar();
};

void Foo::bar() {}
"#,
    )
    .unwrap();

    let mut cmd = tldr_cmd();
    cmd.args([
        "structure",
        temp.path().to_str().unwrap(),
        "--lang",
        "cpp",
        "-q",
    ]);
    let out = cmd.assert().success().get_output().stdout.clone();
    let v: Value = serde_json::from_slice(&out).expect("structure output is not valid JSON");

    let files = v
        .get("files")
        .and_then(Value::as_array)
        .expect("structure.files missing");
    let f0 = files
        .iter()
        .find(|f| {
            f.get("path")
                .and_then(Value::as_str)
                .map(|p| p.ends_with("Foo.cpp"))
                .unwrap_or(false)
        })
        .expect("Foo.cpp not in structure output");

    // The out-of-class definition is a top-level `function_definition`
    // (not inside `field_declaration_list`), so it appears in `definitions`
    // with kind "function", not in `method_infos`. We assert the unqualified
    // name was extracted.
    // (The legacy `functions: [String]` flat array was removed by
    // schema-cleanup-v1 BUG-13 in favor of the canonical `definitions[]`.)
    let definitions = f0
        .get("definitions")
        .and_then(Value::as_array)
        .expect("definitions array missing");
    let fn_names: Vec<&str> = definitions
        .iter()
        .filter(|d| d.get("kind").and_then(Value::as_str) == Some("function"))
        .filter_map(|d| d.get("name").and_then(Value::as_str))
        .collect();
    assert!(
        fn_names.contains(&"bar"),
        "expected 'bar' in definitions[kind=function] (unqualified out-of-class name), got {fn_names:?}"
    );
    // Pre-fix this would have been "" — explicitly verify no empty entries.
    assert!(
        !fn_names.contains(&""),
        "function definitions contain empty name entries: {fn_names:?}"
    );
}
