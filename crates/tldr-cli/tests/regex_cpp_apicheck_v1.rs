//! regex-cpp-apicheck-v1 (v0.5.0 REGEX-CPP): AST gate for the C++ `CPP004`
//! `raw-new` api-check rule.
//!
//! Pre-fix the CPP004 rule was a pure text regex (`\bnew\s+\w`). The `\bnew`
//! word-boundary matches the literal word "new" *anywhere* on a line —
//! including inside string literals and trailing inline content the
//! line-level comment skip can't see. Concretely:
//!
//!   const char* s = "construct a new object";
//!
//! matches `new object` inside the string and reports a phantom raw-`new`
//! allocation. The same shape fires for the word "new" appearing in prose
//! that is not stripped by `is_comment_line` (e.g. a string used as a help
//! message or an embedded code-snippet literal).
//!
//! Fix (AST-driven, per the LU001 `lu001-ast-gate-v1` template): compute a
//! per-file `CppApiCheckContext` once via tree-sitter, holding the set of
//! 1-indexed source lines that contain a real `new_expression` node (the
//! C++ grammar's node kind for an actual `new T(...)` allocation
//! expression). `check_regex_rule` consults the context for CPP004 only;
//! the regex still locates the column, but the finding is suppressed unless
//! the line carries a genuine `new_expression`. Comments and string
//! literals are lexed by tree-sitter as `comment` / `string_literal` nodes,
//! so the word "new" inside them never produces a `new_expression` and can
//! never match. Other C++ rules (CPP001–CPP003, CPP005) and other
//! languages are unaffected.

use std::process::Command;

fn tldr_bin() -> std::path::PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR must be set under cargo test");
    std::path::PathBuf::from(manifest)
        .join("..")
        .join("..")
        .join("target")
        .join("release")
        .join("tldr")
}

fn run_tldr(args: &[&str]) -> (i32, String) {
    let out = Command::new(tldr_bin())
        .args(args)
        .output()
        .expect("failed to run tldr binary");
    let exit = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    (exit, stdout)
}

fn parse_json(out: &str) -> serde_json::Value {
    serde_json::from_str(out).unwrap_or(serde_json::Value::Null)
}

fn cpp004_count(v: &serde_json::Value) -> usize {
    v.get("findings")
        .and_then(|x| x.as_array())
        .map(|arr| {
            arr.iter()
                .filter(|f| {
                    f.get("rule")
                        .and_then(|r| r.get("id"))
                        .and_then(|s| s.as_str())
                        == Some("CPP004")
                })
                .count()
        })
        .unwrap_or(0)
}

fn write_tempfile(contents: &str, name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("regex_cpp_apicheck_v1_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir tmp");
    let path = dir.join(name);
    std::fs::write(&path, contents).expect("write tmp file");
    path
}

// ===========================================================================
// 1. Negative case: the word "new" inside a string literal must NOT flag
//    CPP004. `\bnew\s+\w` matches `new object` inside the string; the AST
//    gate sees only a `string_literal` node (no `new_expression`).
// ===========================================================================
#[test]
fn cpp004_new_in_string_literal_not_flagged() {
    let src = "int main() {\n    const char* s = \"construct a new object\";\n    return 0;\n}\n";
    let path = write_tempfile(src, "new_in_string.cpp");
    let (exit, out) = run_tldr(&["api-check", path.to_str().unwrap(), "--format", "json"]);
    assert!(
        exit == 0 || exit == 1,
        "api-check exit must be 0 or 1; got {}; out={}",
        exit,
        out
    );
    let v = parse_json(&out);
    let count = cpp004_count(&v);
    assert_eq!(
        count, 0,
        "CPP004 must NOT fire on the word `new` inside a string literal; got count={}, out={}",
        count, out
    );
}

// ===========================================================================
// 2. Negative case: the word "new" inside a block comment must NOT flag
//    CPP004 even when other tokens follow it on the line.
// ===========================================================================
#[test]
fn cpp004_new_in_block_comment_not_flagged() {
    let src = "int main() {\n    /* allocate a new buffer in a future revision */\n    return 0;\n}\n";
    let path = write_tempfile(src, "new_in_block_comment.cpp");
    let (exit, out) = run_tldr(&["api-check", path.to_str().unwrap(), "--format", "json"]);
    assert!(exit == 0 || exit == 1, "exit={} out={}", exit, out);
    let v = parse_json(&out);
    let count = cpp004_count(&v);
    assert_eq!(
        count, 0,
        "CPP004 must NOT fire on the word `new` inside a `/* ... */` block comment; got count={}, out={}",
        count, out
    );
}

// ===========================================================================
// 3. Positive non-regression: a REAL `new Foo()` allocation STILL fires.
//    The gate is selective, not blanket.
// ===========================================================================
#[test]
fn cpp004_real_new_expression_still_fires() {
    let src = "struct Foo {};\nint main() {\n    Foo* p = new Foo();\n    return 0;\n}\n";
    let path = write_tempfile(src, "real_new.cpp");
    let (exit, out) = run_tldr(&["api-check", path.to_str().unwrap(), "--format", "json"]);
    assert!(
        exit == 0 || exit == 1,
        "api-check exit must be 0 or 1; got {}; out={}",
        exit,
        out
    );
    let v = parse_json(&out);
    let count = cpp004_count(&v);
    assert!(
        count >= 1,
        "CPP004 MUST still flag a genuine `new Foo()` allocation; the AST gate must be \
         selective, not blanket; got count={}, out={}",
        count,
        out
    );
}

// ===========================================================================
// 4. Mixed case: one real `new` allocation plus a string-literal "new" on a
//    different line — exactly ONE CPP004 finding (the real one), proving the
//    gate filters per-line rather than per-file.
// ===========================================================================
#[test]
fn cpp004_mixed_real_and_string_counts_only_real() {
    let src = "struct Foo {};\nint main() {\n    const char* note = \"please use a new pointer\";\n    Foo* p = new Foo();\n    (void)note;\n    return 0;\n}\n";
    let path = write_tempfile(src, "mixed_new.cpp");
    let (exit, out) = run_tldr(&["api-check", path.to_str().unwrap(), "--format", "json"]);
    assert!(exit == 0 || exit == 1, "exit={} out={}", exit, out);
    let v = parse_json(&out);
    let count = cpp004_count(&v);
    assert_eq!(
        count, 1,
        "CPP004 must fire exactly once — on the real `new Foo()` line, not the string-literal \
         `new` line; got count={}, out={}",
        count, out
    );
}
