//! m116-easy-mechanical-v1 (v0.4.2 M-116)
//!
//! Wave 17h: five mechanical bugs surfaced by the iter-3 audit.
//!
//! 1. **#36 C# multi-line attributes on interfaces** —
//!    `[Serializable]\n[Obsolete(...)]\npublic interface IFoo`. The C#
//!    surface walker previously used the `interface_declaration` node's
//!    start row for the visibility check, but tree-sitter-c-sharp
//!    starts the declaration at the FIRST attribute_list (`[Serializable]`)
//!    rather than the `public interface` line. The check therefore
//!    asked "does line 1 contain `public`?" and got `false`, so the
//!    interface was filtered out.
//!
//! 2. **#41 References: fallback definition kind hardcoded "function"** —
//!    For languages without a wired `check_definition_node` arm
//!    (java/csharp/kotlin/scala/swift/etc.), references promotes
//!    AST-verified `kind=Definition` references into `definitions[]`
//!    using `DefinitionKind::Function`, even when the underlying node
//!    is a class/struct/interface declaration.
//!
//! 3. **#42 Rust async test attributes** — `tldr specs --from-tests`
//!    cheaply early-skipped Rust files lacking `#[test]`. Files with
//!    only `#[tokio::test]` / `#[actix_rt::test]` / `#[async_std::test]`
//!    / `#[smol_potat::test]` were skipped — every async-only test
//!    crate reported zero scanned tests.
//!
//! 4. **#44 Rust nested method-chain assertions** —
//!    `assert!(parse(...).iter().any(|x| ...))`. The recursive
//!    `first_callable_inside` / `find_rust_macro_inline_call` walked
//!    into closure bodies and method chains and picked an inner
//!    chained method name (`any`) as the FUT instead of the outermost
//!    semantically-test-relevant function (`parse`).
//!
//! 5. **#45 `definition --symbol` wrong column on shared-line decl** —
//!    `let x = bar(); fn bar() ...`. `locate_symbol_line_column`
//!    text-finds the FIRST whole-word occurrence of the symbol on the
//!    reported line, which is the call site, not the definition.
//!    AST-derived column from the definition's name child gives the
//!    correct value.

use assert_cmd::Command;
use serde_json::Value;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

fn run_json(args: &[&str]) -> Option<Value> {
    let output = tldr_cmd().args(args).output().expect("run tldr");
    let stdout = String::from_utf8(output.stdout).ok()?;
    serde_json::from_str(&stdout).ok()
}

// =============================================================================
// Acceptance 1 — #36: C# interface with multi-line attributes must surface.
// =============================================================================

#[test]
fn test_m116_csharp_multiline_attrs_interface_surfaces() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("IFoo.cs");
    std::fs::write(
        &path,
        "[Serializable]\n\
         [Obsolete(\"use Bar\")]\n\
         public interface IFoo\n\
         {\n\
             string Name { get; }\n\
             void DoWork(int n);\n\
         }\n\
         \n\
         public interface ISimpleInterface\n\
         {\n\
             int Calc();\n\
         }\n",
    )
    .unwrap();

    let json = run_json(&["surface", path.to_str().unwrap(), "--format", "json"])
        .expect("csharp surface should return JSON");

    let names: Vec<String> = json
        .get("apis")
        .and_then(|v| v.as_array())
        .expect(".apis[] must be present")
        .iter()
        .filter_map(|a| a.get("qualified_name").and_then(|v| v.as_str()))
        .map(|s| s.to_string())
        .collect();

    // The attribute-decorated interface MUST appear (regression: it was
    // silently filtered because visibility was checked at the
    // attribute_list line rather than the `public interface` line).
    assert!(
        names.iter().any(|n| n.ends_with("IFoo")),
        "multi-line-attribute interface `IFoo` missing from surface: {:?}",
        names
    );
    // Sibling vanilla interface must still appear (anchors the fix).
    assert!(
        names.iter().any(|n| n.ends_with("ISimpleInterface")),
        "sibling interface `ISimpleInterface` missing: {:?}",
        names
    );
}

// =============================================================================
// Acceptance 2 — #41: references definition kind reflects AST shape, not
// a hardcoded "function" fallback.
// =============================================================================

#[test]
fn test_m116_references_class_definition_kind_is_not_function() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("MyClass.java");
    std::fs::write(
        &path,
        "package com.example;\n\
         \n\
         public class MyClass {\n\
             public void foo() {\n\
                 System.out.println(\"hi\");\n\
             }\n\
         }\n",
    )
    .unwrap();

    let json = run_json(&[
        "references",
        "MyClass",
        path.to_str().unwrap(),
        "--include-definition",
        "--format",
        "json",
    ])
    .expect("references should return JSON");

    let kind = json
        .get("definition")
        .and_then(|d| d.get("kind"))
        .and_then(|k| k.as_str())
        .expect(".definition.kind must be present");

    // The Java `class MyClass` AST node is a class declaration, NOT a
    // function. The fallback path previously hardcoded "function" for
    // Java/C#/Kotlin/Scala/Swift (no per-language `check_definition`
    // arm wired).
    assert_ne!(
        kind, "function",
        "class definition mislabelled as 'function' — fallback hardcoded the wrong kind"
    );
    assert_eq!(
        kind, "class",
        "expected class definition kind for `class MyClass`, got {:?}",
        kind
    );

    // The plural `definitions[]` array must agree with the singular field.
    let defs = json
        .get("definitions")
        .and_then(|v| v.as_array())
        .expect(".definitions[] must be present");
    let any_class = defs
        .iter()
        .any(|d| d.get("kind").and_then(|k| k.as_str()) == Some("class"));
    assert!(
        any_class,
        "definitions[] must include a class entry, got: {:?}",
        defs
    );
}

// =============================================================================
// Acceptance 3 — #42: Rust async test attributes are recognised.
// =============================================================================

#[test]
fn test_m116_rust_async_test_attributes_recognised() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("async_tests.rs");
    std::fs::write(
        &path,
        "fn add(a: i32, b: i32) -> i32 { a + b }\n\
         \n\
         #[tokio::test]\n\
         async fn test_add_tokio() {\n\
             assert_eq!(add(2, 3), 5);\n\
         }\n\
         \n\
         #[actix_rt::test]\n\
         async fn test_add_actix() {\n\
             assert_eq!(add(1, 1), 2);\n\
         }\n\
         \n\
         #[async_std::test]\n\
         async fn test_add_async_std() {\n\
             assert_eq!(add(0, 0), 0);\n\
         }\n",
    )
    .unwrap();

    let json = run_json(&[
        "specs",
        "--from-tests",
        path.to_str().unwrap(),
        "--format",
        "json",
    ])
    .expect("rust specs should return JSON");

    let summary = json.get("summary").expect("summary missing");

    // All three async tests MUST be counted. Pre-fix the file was
    // skipped because `source.contains("#[test]")` was false (only
    // `#[tokio::test]` etc.).
    let scanned = summary
        .get("test_functions_scanned")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    assert_eq!(
        scanned, 3,
        "expected 3 async tests recognised, got {}: {:?}",
        scanned, summary
    );

    // And at least one spec was harvested for `add` from the
    // `assert_eq!(add(...), N)` shape.
    let funcs = json
        .get("functions")
        .and_then(|v| v.as_array())
        .expect(".functions[] missing");
    let has_add_spec = funcs.iter().any(|f| {
        f.get("function_name").and_then(|v| v.as_str()) == Some("add")
    });
    assert!(
        has_add_spec,
        "expected `add` FUT spec extracted from `assert_eq!(add(..), ..)` inside async tests; got: {:?}",
        funcs
    );
}

// =============================================================================
// Acceptance 4 — #44: Rust nested method-chain assertions don't pick
// inner closure / chain method names as the FUT.
// =============================================================================

#[test]
fn test_m116_rust_nested_chain_assert_does_not_pick_chain_helper() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("chain_test.rs");
    std::fs::write(
        &path,
        "fn parse(s: &str) -> Vec<i32> {\n    s.split(',').filter_map(|p| p.parse().ok()).collect()\n}\n\
         \n\
         #[test]\n\
         fn test_parse_chain() {\n    let result = parse(\"1,2,3\");\n    assert!(result.iter().any(|x| *x == 2));\n}\n",
    )
    .unwrap();

    let json = run_json(&[
        "specs",
        "--from-tests",
        path.to_str().unwrap(),
        "--format",
        "json",
    ])
    .expect("rust specs should return JSON");

    let funcs = json
        .get("functions")
        .and_then(|v| v.as_array())
        .expect(".functions[] missing");

    let fnames: Vec<String> = funcs
        .iter()
        .filter_map(|f| f.get("function_name").and_then(|v| v.as_str()))
        .map(|s| s.to_string())
        .collect();

    // Pre-fix the FUT was `any` (the inner Iterator::any method on a
    // chained iterator). It MUST NOT be selected — that method is a
    // closure-context helper, not the function being tested.
    assert!(
        !fnames.iter().any(|n| n == "any"),
        "FUT mis-picked from method chain (`any` is a closure-context iterator helper, not a FUT): {:?}",
        fnames
    );
    assert!(
        !fnames.iter().any(|n| n == "iter"),
        "FUT mis-picked from method chain (`iter`): {:?}",
        fnames
    );
}

// =============================================================================
// Acceptance 5 — #45: `definition --symbol` returns the AST-derived
// column of the definition's name child, not the first text occurrence.
// =============================================================================

#[test]
fn test_m116_definition_column_uses_ast_not_first_text_occurrence() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("shared_line.rs");
    // `bar()` (call site at col 13) appears BEFORE `fn bar` (the
    // definition at col 23) on the same line. Pre-fix the column
    // returned was 13 (the call site); the correct AST column is 23
    // (the name node inside the function_item).
    std::fs::write(
        &path,
        "fn main() {\n    let x = bar(); fn bar() -> i32 { 42 }\n}\n",
    )
    .unwrap();

    let json = run_json(&[
        "definition",
        "--file",
        path.to_str().unwrap(),
        "--symbol",
        "bar",
        "--format",
        "json",
    ])
    .expect("definition should return JSON");

    let column = json
        .get("definition")
        .and_then(|d| d.get("column"))
        .and_then(|c| c.as_u64())
        .expect(".definition.column missing");

    assert_eq!(
        column, 23,
        "expected AST-derived column 23 (`fn bar` definition), got {} — \
         pre-fix textual find returned the first occurrence (the call site at col 13)",
        column
    );
}
