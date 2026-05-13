//! cpp-explain-refs-cleanup-v1: regression coverage for v0.4.2 audit bugs
//! BUG-CPP-P20-03 (`references` definitions[] empty for cpp qualified names)
//! and BUG-CPP-P20-04 (`explain` emits `static_cast` / `TIXMLASSERT` as
//! false-positive callees and `num_blocks` disagrees with the canonical
//! CFG-derived `context.blocks` count for the same C++ function).
//!
//! Background
//! ----------
//! Pre-fix the C++ surfaces of three different commands disagreed on the
//! same function:
//!
//! * `tldr references XMLDocument::Parse /tmp/repos/cpp-tinyxml2` listed
//!   the out-of-class function-definition lines under `references[]` with
//!   `kind: other` and emitted `definitions: []`. `find_definitions` had
//!   no C++ arm (only python / typescript / javascript / go / rust), and
//!   the AST verifier mis-classified the position because the candidate
//!   column landed on the first identifier of a `qualified_identifier`
//!   (`XMLDocument`) rather than on the whole qualified name — so
//!   `find_exact_match_node` (which only walks DOWN) never found a node
//!   whose text equalled `"XMLDocument::Parse"`.
//!
//! * `tldr explain tinyxml2.cpp XMLDocument::Parse` listed both
//!   `static_cast` (a `cast_expression` masquerading as a
//!   `call_expression` whose `function` field is a `template_function`)
//!   and `TIXMLASSERT` (an all-uppercase preprocessor macro) under
//!   `callees[]`. Neither is a real callee.
//!
//! * The same `explain` invocation reported `complexity.num_blocks = 4`
//!   from a Python-shaped local walker (only `if_statement` /
//!   `for_statement` / `while_statement` / `try_statement` /
//!   `except_clause` increment), while `tldr context XMLDocument::Parse`
//!   reported `blocks = 14` from the canonical CFG. The cross-command
//!   contract for the cyclomatic counter (BUG-P19-07) was extended in
//!   this fix to also cover `num_blocks` so explain delegates to the
//!   canonical CFG when available.

use assert_cmd::prelude::*;
use serde_json::Value;
use std::fs;
use std::process::Command;
use tempfile::TempDir;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

/// BUG-CPP-P20-03: when an out-of-class function definition
/// `XMLError XMLDocument::Parse(...)` is the textual match for
/// `references XMLDocument::Parse`, the corresponding entry must be
/// promoted from the unified `references[]` list into the canonical
/// `definitions[]` slot. Pre-fix `definitions[]` was empty.
#[test]
fn cpp_references_separates_definitions() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("tinyxml2.cpp");
    fs::write(
        &path,
        r#"namespace tinyxml2 {

class XMLDocument {
public:
    int Parse(const char* xml);
};

int XMLDocument::Parse(const char* xml) {
    if (!xml) {
        return 1;
    }
    return 0;
}

void caller() {
    XMLDocument doc;
    doc.Parse("hi");
}

}
"#,
    )
    .unwrap();

    let mut cmd = tldr_cmd();
    cmd.args([
        "references",
        "XMLDocument::Parse",
        temp.path().to_str().unwrap(),
        "-q",
    ]);
    let out = cmd.assert().success().get_output().stdout.clone();
    let v: Value =
        serde_json::from_slice(&out).expect("references output is not valid JSON");

    let defs = v
        .get("definitions")
        .and_then(|d| d.as_array())
        .expect("definitions[] missing");
    assert!(
        !defs.is_empty(),
        "cpp qualified-name references must emit at least one definition; got {v:#}"
    );

    // At least one of the emitted definitions must be the out-of-class
    // definition on the line that begins with `int XMLDocument::Parse`.
    let def_lines: Vec<u64> = defs
        .iter()
        .filter_map(|d| d.get("line").and_then(|l| l.as_u64()))
        .collect();
    assert!(
        def_lines.iter().any(|&l| l == 8),
        "expected definition entry on line 8 (out-of-class definition); got lines {def_lines:?}"
    );
}

/// BUG-CPP-P20-04 part-1: `static_cast<T>(x)`, `const_cast<T>(x)`,
/// `dynamic_cast<T>(x)`, `reinterpret_cast<T>(x)`, and all-uppercase
/// preprocessor-macro identifiers (e.g. `TIXMLASSERT`) must NOT appear in
/// `callees[]`. The first four are cast expressions (no function call
/// happens); the last is a macro expansion, also not a runtime call.
#[test]
fn cpp_explain_excludes_static_cast_callees() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("a.cpp");
    fs::write(
        &path,
        r#"int real_callee(int n) { return n; }

int caller(double v) {
    int x = static_cast<int>(v);
    int y = const_cast<int&>(x);
    int z = dynamic_cast<int>(x);
    int w = reinterpret_cast<int>(v);
    TIXMLASSERT(x > 0);
    return real_callee(x);
}
"#,
    )
    .unwrap();

    let mut cmd = tldr_cmd();
    cmd.args([
        "explain",
        path.to_str().unwrap(),
        "caller",
        "-q",
    ]);
    let out = cmd.assert().success().get_output().stdout.clone();
    let v: Value =
        serde_json::from_slice(&out).expect("explain output is not valid JSON");

    let callees = v
        .get("callees")
        .and_then(|c| c.as_array())
        .expect("callees[] missing");
    let names: Vec<&str> = callees
        .iter()
        .filter_map(|c| c.get("name").and_then(|n| n.as_str()))
        .collect();

    for forbidden in [
        "static_cast",
        "const_cast",
        "dynamic_cast",
        "reinterpret_cast",
        "TIXMLASSERT",
    ] {
        assert!(
            !names.iter().any(|n| *n == forbidden),
            "callees[] must not contain `{forbidden}`; got {names:?}"
        );
    }

    // The real call must still be present.
    assert!(
        names.iter().any(|n| *n == "real_callee"),
        "real_callee should still appear in callees[]; got {names:?}"
    );
}

/// BUG-CPP-P20-04 part-2: `tldr explain`'s `complexity.num_blocks` must
/// match `tldr context`'s `blocks` for the same C++ function. Pre-fix
/// explain used a Python-shaped node-kind enumerator (only `if_statement`
/// / `for_statement` / `while_statement` / `try_statement` /
/// `except_clause`), so a function with `switch_statement`, `case`
/// clauses, `do_statement`, etc. was severely under-counted (4 vs 14 in
/// the tinyxml2 case).
#[test]
fn cpp_explain_blocks_match_context() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("b.cpp");
    fs::write(
        &path,
        r#"int branchy(int x) {
    if (x == 0) {
        return 0;
    }
    if (x == 1) {
        return 1;
    }
    switch (x) {
        case 2: return 2;
        case 3: return 3;
        default: break;
    }
    for (int i = 0; i < x; ++i) {
        if (i % 2 == 0) {
            x++;
        }
    }
    return x;
}
"#,
    )
    .unwrap();

    // Get explain.complexity.num_blocks
    let mut e = tldr_cmd();
    e.args(["explain", path.to_str().unwrap(), "branchy", "-q"]);
    let explain_out = e.assert().success().get_output().stdout.clone();
    let ev: Value =
        serde_json::from_slice(&explain_out).expect("explain output is not valid JSON");
    let explain_blocks = ev
        .get("complexity")
        .and_then(|c| c.get("num_blocks"))
        .and_then(|n| n.as_u64())
        .expect("explain.complexity.num_blocks missing");

    // Get context.blocks for the same function
    let mut c = tldr_cmd();
    c.args([
        "context",
        "branchy",
        temp.path().to_str().unwrap(),
        "--lang",
        "cpp",
        "-q",
    ]);
    let ctx_out = c.assert().success().get_output().stdout.clone();
    let cv: Value =
        serde_json::from_slice(&ctx_out).expect("context output is not valid JSON");
    let functions = cv
        .get("functions")
        .and_then(|f| f.as_array())
        .expect("context.functions[] missing");
    let entry = functions
        .iter()
        .find(|f| f.get("name").and_then(|n| n.as_str()) == Some("branchy"))
        .expect("context.functions[] missing `branchy`");
    let context_blocks = entry
        .get("blocks")
        .and_then(|b| b.as_u64())
        .expect("context.functions[].blocks missing");

    assert_eq!(
        explain_blocks, context_blocks,
        "explain.num_blocks ({explain_blocks}) must match context.blocks ({context_blocks}) \
         for the same C++ function `branchy`"
    );
}
