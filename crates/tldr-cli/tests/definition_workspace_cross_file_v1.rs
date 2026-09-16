//! definition-workspace-cross-file-v1: workspace-wide cross-file go-to-definition
//!
//! Before this milestone, `tldr definition <file> <line> <col>` only resolved
//! cross-file when an explicit `--project <root>` flag was supplied. Without
//! it, a cursor on an imported symbol returned the import line itself
//! (`kind=module`) instead of the actual function/class/constant in the
//! source file.
//!
//! After this milestone, the project root is auto-detected by walking up
//! ancestors of the source file looking for `.git`, `Cargo.toml`,
//! `pyproject.toml`, `package.json`, `pom.xml`, etc. The new `--workspace`
//! flag (default `true`) controls auto-detection — passing
//! `--workspace=false` opts back into the file-only behaviour.
//!
//! Languages covered by these tests: Python, TypeScript, Rust, Java. Other
//! languages benefit from the same auto-detection plumbing because the
//! underlying generic project walker (`resolve_cross_file_walk`) already
//! supports them — it just needs a workspace root to be useful.

use serde_json::Value;
use std::fs;
use std::process::Command;
use tempfile::TempDir;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

/// Mark `dir` as a project root by creating a `.git` directory inside it
/// (the cheapest and most universal marker recognised by
/// `find_workspace_root`).
fn mark_project_root(dir: &std::path::Path) {
    fs::create_dir_all(dir.join(".git")).expect("create .git marker");
}

/// Run `tldr definition <file> <line> <col>` without `--project` and parse
/// its JSON output. The harness deliberately does NOT pass `--project` —
/// the whole point of these tests is to exercise auto-detection.
fn run_definition_no_project(file: &std::path::Path, line: u32, col: u32) -> Value {
    let mut cmd = tldr_cmd();
    cmd.args([
        "definition",
        file.to_str().unwrap(),
        &line.to_string(),
        &col.to_string(),
        "-q",
    ]);
    let out = cmd.output().expect("tldr ran");
    assert!(
        out.status.success(),
        "tldr definition failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("valid JSON")
}

#[test]
fn test_definition_cross_file_python_from_import() {
    // Workspace:
    //   <root>/.git/
    //   <root>/pkg/__init__.py
    //   <root>/pkg/util.py    -> def helper(): ...
    //   <root>/app.py         -> from pkg.util import helper
    //                            def main(): helper()
    let tmp = TempDir::new().unwrap();
    mark_project_root(tmp.path());
    fs::create_dir_all(tmp.path().join("pkg")).unwrap();
    fs::write(tmp.path().join("pkg/__init__.py"), "").unwrap();
    fs::write(
        tmp.path().join("pkg/util.py"),
        "def helper():\n    return 42\n",
    )
    .unwrap();
    let app = tmp.path().join("app.py");
    fs::write(
        &app,
        "from pkg.util import helper\n\ndef main():\n    helper()\n",
    )
    .unwrap();

    // Cursor on `helper()` usage at line 4, col 4.
    let result = run_definition_no_project(&app, 4, 4);
    let kind = result["symbol"]["kind"].as_str().unwrap();
    let file = result["definition"]["file"].as_str().unwrap();
    let line = result["definition"]["line"].as_u64().unwrap();

    assert_eq!(
        kind, "function",
        "expected kind=function (resolved cross-file), got {kind}: {result}"
    );
    assert!(
        file.ends_with("pkg/util.py"),
        "expected definition in pkg/util.py, got {file}"
    );
    assert_eq!(line, 1, "helper() is defined on line 1 of util.py");
}

#[test]
fn test_definition_cross_file_typescript_named_import() {
    // Workspace:
    //   <root>/.git/
    //   <root>/foo.ts          -> export function helper() { ... }
    //   <root>/app.ts          -> import { helper } from "./foo"; helper();
    let tmp = TempDir::new().unwrap();
    mark_project_root(tmp.path());
    fs::write(
        tmp.path().join("foo.ts"),
        "export function helper(): number {\n  return 42;\n}\n",
    )
    .unwrap();
    let app = tmp.path().join("app.ts");
    fs::write(
        &app,
        "import { helper } from \"./foo\";\n\nfunction main() {\n  helper();\n}\n",
    )
    .unwrap();

    // Cursor on `helper()` usage at line 4, col 2.
    let result = run_definition_no_project(&app, 4, 2);
    let kind = result["symbol"]["kind"].as_str().unwrap();
    let file = result["definition"]["file"].as_str().unwrap();

    assert_eq!(
        kind, "function",
        "expected kind=function, got {kind}: {result}"
    );
    assert!(
        file.ends_with("foo.ts"),
        "expected definition in foo.ts, got {file}"
    );
}

#[test]
fn test_definition_cross_file_rust_use() {
    // Workspace:
    //   <root>/Cargo.toml      (project root marker)
    //   <root>/src/main.rs     -> mod foo; use foo::bar::helper; helper();
    //   <root>/src/foo/mod.rs  -> pub mod bar;
    //   <root>/src/foo/bar.rs  -> pub fn helper() -> i32 { ... }
    let tmp = TempDir::new().unwrap();
    fs::write(
        tmp.path().join("Cargo.toml"),
        "[package]\nname = \"x\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();
    fs::create_dir_all(tmp.path().join("src/foo")).unwrap();
    fs::write(
        tmp.path().join("src/foo/bar.rs"),
        "pub fn helper() -> i32 {\n    42\n}\n",
    )
    .unwrap();
    fs::write(tmp.path().join("src/foo/mod.rs"), "pub mod bar;\n").unwrap();
    let main = tmp.path().join("src/main.rs");
    fs::write(
        &main,
        "mod foo;\nuse foo::bar::helper;\n\nfn main() {\n    helper();\n}\n",
    )
    .unwrap();

    // Cursor on `helper()` usage at line 5, col 4.
    let result = run_definition_no_project(&main, 5, 4);
    let kind = result["symbol"]["kind"].as_str().unwrap();
    let file = result["definition"]["file"].as_str().unwrap();

    assert_eq!(
        kind, "function",
        "expected kind=function, got {kind}: {result}"
    );
    assert!(
        file.ends_with("bar.rs"),
        "expected definition in foo/bar.rs, got {file}"
    );
}

#[test]
fn test_definition_cross_file_java_import() {
    // Workspace:
    //   <root>/.git/
    //   <root>/com/example/Foo.java -> public class Foo { }
    //   <root>/Main.java            -> import com.example.Foo; new Foo();
    let tmp = TempDir::new().unwrap();
    mark_project_root(tmp.path());
    fs::create_dir_all(tmp.path().join("com/example")).unwrap();
    fs::write(
        tmp.path().join("com/example/Foo.java"),
        "package com.example;\npublic class Foo {\n}\n",
    )
    .unwrap();
    let main = tmp.path().join("Main.java");
    fs::write(
        &main,
        "import com.example.Foo;\n\npublic class Main {\n    public static void main(String[] args) {\n        Foo f = new Foo();\n    }\n}\n",
    )
    .unwrap();

    // Cursor on the `Foo` type annotation in `Foo f = new Foo();` at
    // line 5, col 8 (the column lands on the first `F` of `Foo`).
    let result = run_definition_no_project(&main, 5, 8);
    let kind = result["symbol"]["kind"].as_str().unwrap();
    let file = result["definition"]["file"].as_str().unwrap();

    assert_eq!(kind, "class", "expected kind=class, got {kind}: {result}");
    assert!(
        file.ends_with("Foo.java"),
        "expected definition in com/example/Foo.java, got {file}"
    );
}

#[test]
fn test_definition_workspace_false_keeps_legacy_behaviour() {
    // Sanity-check: with --workspace=false and no --project, we should
    // get the legacy "import line" result (kind=module pointing at the
    // import in the same file), not cross-file resolution.
    let tmp = TempDir::new().unwrap();
    mark_project_root(tmp.path());
    fs::create_dir_all(tmp.path().join("pkg")).unwrap();
    fs::write(tmp.path().join("pkg/__init__.py"), "").unwrap();
    fs::write(
        tmp.path().join("pkg/util.py"),
        "def helper():\n    return 42\n",
    )
    .unwrap();
    let app = tmp.path().join("app.py");
    fs::write(
        &app,
        "from pkg.util import helper\n\ndef main():\n    helper()\n",
    )
    .unwrap();

    let mut cmd = tldr_cmd();
    cmd.args([
        "definition",
        app.to_str().unwrap(),
        "4",
        "4",
        "--workspace=false",
        "-q",
    ]);
    let out = cmd.output().expect("tldr ran");
    assert!(out.status.success());
    let result: Value = serde_json::from_slice(&out.stdout).unwrap();
    let kind = result["symbol"]["kind"].as_str().unwrap();
    let file = result["definition"]["file"].as_str().unwrap();

    assert_eq!(
        kind, "module",
        "with --workspace=false expected kind=module (import line), got {kind}: {result}"
    );
    assert!(
        file.ends_with("app.py"),
        "with --workspace=false expected import line in app.py, got {file}"
    );
}

#[test]
fn test_find_workspace_root_helper_basic() {
    // The `find_workspace_root` helper is `pub(crate)` so we cannot call
    // it directly from an external test crate. Verify the behaviour is
    // wired correctly by running the binary against a workspace whose
    // root marker is `.git` two directories above the source file.
    let tmp = TempDir::new().unwrap();
    mark_project_root(tmp.path());
    fs::create_dir_all(tmp.path().join("a/b")).unwrap();
    fs::write(
        tmp.path().join("a/b/util.py"),
        "def helper():\n    return 42\n",
    )
    .unwrap();
    let app = tmp.path().join("a/b/app.py");
    fs::write(
        &app,
        "from a.b.util import helper\n\ndef main():\n    helper()\n",
    )
    .unwrap();

    // Auto-detection should locate the .git two levels up and resolve
    // the import successfully.
    let result = run_definition_no_project(&app, 4, 4);
    let kind = result["symbol"]["kind"].as_str().unwrap();
    let file = result["definition"]["file"].as_str().unwrap();

    assert_eq!(
        kind, "function",
        "expected kind=function (auto-root-detection works), got {kind}: {result}"
    );
    assert!(
        file.ends_with("util.py"),
        "expected definition in a/b/util.py, got {file}"
    );
}
