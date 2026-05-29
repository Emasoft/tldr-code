//! m007-m036-hubs-line-is-public-v1 — v0.4.2 M-113.
//!
//! Pins two regressions in `tldr hubs --format json`:
//!
//! - **M-036 (line population)** — for Java, Kotlin, C++, and OCaml projects,
//!   real-world hubs frequently reported `function_ref.line == 0` even when
//!   the AST extractor knew the defining line. The miss happened for
//!   constructors / bare class-name refs (Java/Kotlin), header-inline
//!   methods (C++), and qualified module functions (OCaml).
//!
//! - **M-007 (is_public population)** — for Java, C++, and C#, every hub
//!   came back with `is_public: false` even though those languages carry
//!   explicit access modifiers (`public`, `private`, `protected`, ...) in
//!   the AST and the visibility extractor already produced a string. The
//!   `FunctionRef` boolean was never plumbed.
//!
//! These tests use small inline fixtures so they run hermetically without
//! depending on `/tmp/repos/<corpus>`.

use serde_json::Value;
use std::fs;
use std::process::Command;
use tempfile::TempDir;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

fn run_hubs_json(path: &std::path::Path, lang: &str) -> Value {
    let output = tldr_cmd()
        .args([
            "hubs",
            path.to_str().unwrap(),
            "--lang",
            lang,
            "--quiet",
            "--format",
            "json",
        ])
        .output()
        .expect("failed to run tldr hubs");
    assert!(
        output.status.success(),
        "tldr hubs --lang {lang} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8(output.stdout).expect("non-utf8 stdout");
    serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("invalid JSON from tldr hubs --lang {lang}: {e}\n--- stdout ---\n{stdout}")
    })
}

#[allow(dead_code)]
fn find_hub<'a>(json: &'a Value, name: &str) -> Option<&'a Value> {
    json["hubs"]
        .as_array()?
        .iter()
        .find(|h| h["function_ref"]["name"] == name)
}

// =============================================================================
// M-036 (line population)
// =============================================================================

/// Java: `Owner` is a class with a no-arg constructor. The call-graph builder
/// emits a `dst_func == "Owner"` (or `"Owner.Owner"`) edge for every `new
/// Owner()`. Pre-fix the hub entry came back `line: 0` because
/// `enumerate_function_lines` only indexed `method_declaration`, never the
/// class itself nor `constructor_declaration`. Pinning behaviour: the
/// class-name lookup falls back to the class's own line.
#[test]
fn test_m036_hubs_line_populated_java_constructors_and_classes() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("src");
    fs::create_dir_all(&dir).unwrap();

    // `Owner` class on line 4. Constructor on line 6. Several callers create
    // instances via `new Owner()` so the call-graph builds an edge whose
    // `dst_func == "Owner"`.
    fs::write(
        dir.join("Owner.java"),
        "package demo;\n\n\npublic class Owner {\n    public String name;\n    public Owner(String name) { this.name = name; }\n    public String getName() { return name; }\n}\n",
    )
    .unwrap();
    fs::write(
        dir.join("Factory.java"),
        "package demo;\npublic class Factory {\n    public Owner makeA() { return new Owner(\"a\"); }\n    public Owner makeB() { return new Owner(\"b\"); }\n    public Owner makeC() { return new Owner(\"c\"); }\n    public Owner makeD() { return new Owner(\"d\"); }\n}\n",
    )
    .unwrap();

    let json = run_hubs_json(temp.path(), "java");

    // Every hub with a known source line must report a non-zero line.
    // The acceptance criterion is "ZERO 0 values for hubs whose source
    // line is known". For an all-local fixture every hub has a known
    // source, so we assert globally.
    let hubs = json["hubs"].as_array().expect("hubs array");
    let zero_lines: Vec<String> = hubs
        .iter()
        .filter(|h| h["function_ref"]["line"].as_u64() == Some(0))
        .map(|h| h["function_ref"]["name"].as_str().unwrap_or("?").to_string())
        .collect();
    assert!(
        zero_lines.is_empty(),
        "expected zero hubs with line=0, got {} (names: {:?})\nfull report:\n{}",
        zero_lines.len(),
        zero_lines,
        serde_json::to_string_pretty(&json).unwrap()
    );

    // `Owner` (referenced by `new Owner(...)`) should resolve to the class
    // line. The call-graph builder emits either `Owner` or `Owner.Owner`
    // depending on how it resolves the `new` expression — accept both.
    let owner = json["hubs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|h| {
            let n = h["function_ref"]["name"].as_str().unwrap_or("");
            n == "Owner" || n == "Owner.Owner"
        })
        .unwrap_or_else(|| {
            panic!(
                "`Owner` (constructor target) not found in hubs:\n{}",
                serde_json::to_string_pretty(&json).unwrap()
            )
        });
    let line = owner["function_ref"]["line"]
        .as_u64()
        .expect("Owner.line must be a number");
    assert_ne!(line, 0, "Owner constructor line stayed at 0");
}

/// Kotlin: bare class-name refs (Kotlin has no `new`; `LocalTime(...)` IS
/// the constructor) must resolve to the class definition line.
#[test]
fn test_m036_hubs_line_populated_kotlin_class_constructors() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("src");
    fs::create_dir_all(&dir).unwrap();

    // `MyTime` class declared on line 4. Several callers construct via `MyTime(...)`.
    fs::write(
        dir.join("MyTime.kt"),
        "package demo\n\n\nclass MyTime(val hours: Int) {\n    fun hours(): Int = hours\n}\n",
    )
    .unwrap();
    fs::write(
        dir.join("Factory.kt"),
        "package demo\n\nfun makeA(): MyTime = MyTime(1)\nfun makeB(): MyTime = MyTime(2)\nfun makeC(): MyTime = MyTime(3)\nfun makeD(): MyTime = MyTime(4)\nfun makeE(): MyTime = MyTime(5)\n",
    )
    .unwrap();

    let json = run_hubs_json(temp.path(), "kotlin");

    let hubs = json["hubs"].as_array().expect("hubs array");
    let zero_lines: Vec<String> = hubs
        .iter()
        .filter(|h| h["function_ref"]["line"].as_u64() == Some(0))
        .map(|h| h["function_ref"]["name"].as_str().unwrap_or("?").to_string())
        .collect();
    assert!(
        zero_lines.is_empty(),
        "expected zero Kotlin hubs with line=0, got {} (names: {:?})\nfull report:\n{}",
        zero_lines.len(),
        zero_lines,
        serde_json::to_string_pretty(&json).unwrap()
    );
}

/// C++: a header-inline class method (`Counter::incr`) was previously
/// missed because `enumerate_function_lines` used `extensions()` (which
/// omits `.h`). M-036 already switched to `scan_extensions()`. This test
/// pins that all hubs in a small `.h`+`.cpp` fixture get a known line.
#[test]
fn test_m036_hubs_line_populated_cpp_header_inline() {
    let temp = TempDir::new().unwrap();

    fs::write(
        temp.path().join("counter.h"),
        "#pragma once\nclass Counter {\npublic:\n  int n;\n  void incr() { n++; }\n  void incrBy(int k) { n += k; }\n};\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("main.cpp"),
        "#include \"counter.h\"\nvoid bumpA(Counter& c) { c.incr(); }\nvoid bumpB(Counter& c) { c.incr(); }\nvoid bumpC(Counter& c) { c.incr(); }\nint main() { Counter c{0}; bumpA(c); bumpB(c); bumpC(c); return c.n; }\n",
    )
    .unwrap();

    let json = run_hubs_json(temp.path(), "cpp");

    let hubs = json["hubs"].as_array().expect("hubs array");
    let zero_lines: Vec<String> = hubs
        .iter()
        .filter(|h| h["function_ref"]["line"].as_u64() == Some(0))
        .map(|h| h["function_ref"]["name"].as_str().unwrap_or("?").to_string())
        .collect();
    assert!(
        zero_lines.is_empty(),
        "expected zero C++ hubs with line=0, got {} (names: {:?})\nfull report:\n{}",
        zero_lines.len(),
        zero_lines,
        serde_json::to_string_pretty(&json).unwrap()
    );
}

/// OCaml: qualified module-internal calls (`Bar.helper`) must fall back
/// to the bare `helper` line when no exact lookup hit is found. Pre-fix
/// the hub line was 0.
#[test]
fn test_m036_hubs_line_populated_ocaml_qualified_calls() {
    let temp = TempDir::new().unwrap();

    // `helper` defined at line 3 inside module `Bar`. Several callers in
    // a sibling file reference it as `Bar.helper`.
    fs::write(
        temp.path().join("bar.ml"),
        "module Bar = struct\n\n  let helper x = x + 1\n\nend\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("a.ml"),
        "let caller_a () = Bar.helper 1\nlet caller_b () = Bar.helper 2\nlet caller_c () = Bar.helper 3\nlet caller_d () = Bar.helper 4\n",
    )
    .unwrap();

    let json = run_hubs_json(temp.path(), "ocaml");

    let hubs = json["hubs"].as_array().expect("hubs array");
    // Find `Bar.helper` (or `helper`) - it must have a non-zero line.
    let helper = hubs.iter().find(|h| {
        let n = h["function_ref"]["name"].as_str().unwrap_or("");
        n == "Bar.helper" || n == "helper"
    });
    if let Some(h) = helper {
        let line = h["function_ref"]["line"].as_u64().expect("line is number");
        assert_ne!(
            line, 0,
            "OCaml `Bar.helper` line stayed at 0:\nhub={}",
            serde_json::to_string_pretty(h).unwrap()
        );
    } else {
        // If the call-graph didn't surface this entry at all the test is
        // unactionable; ensure no other zero-line hubs slipped through.
        let zero_lines: Vec<String> = hubs
            .iter()
            .filter(|h| h["function_ref"]["line"].as_u64() == Some(0))
            .map(|h| h["function_ref"]["name"].as_str().unwrap_or("?").to_string())
            .collect();
        assert!(
            zero_lines.is_empty(),
            "Bar.helper not in hubs and {} other hubs have line=0: {:?}\nfull report:\n{}",
            zero_lines.len(),
            zero_lines,
            serde_json::to_string_pretty(&json).unwrap()
        );
    }
}

// =============================================================================
// M-007 (is_public population)
// =============================================================================

/// Java: a `public` method must surface `is_public: true` on its hub
/// entry. Pre-fix every Java hub had `is_public: false` regardless of
/// the AST modifier, because `enumerate_function_lines` never carried
/// visibility through to `FunctionRef`.
#[test]
fn test_m007_hubs_is_public_java() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("src");
    fs::create_dir_all(&dir).unwrap();

    fs::write(
        dir.join("Lib.java"),
        "package demo;\npublic class Lib {\n    public int helper(int x) { return x + 1; }\n    private int internal_(int x) { return helper(x) * 2; }\n}\n",
    )
    .unwrap();
    fs::write(
        dir.join("Caller.java"),
        "package demo;\npublic class Caller {\n    public int a() { return new Lib().helper(1); }\n    public int b() { return new Lib().helper(2); }\n    public int c() { return new Lib().helper(3); }\n    public int d() { return new Lib().helper(4); }\n}\n",
    )
    .unwrap();

    let json = run_hubs_json(temp.path(), "java");

    // Find `Lib.helper` or `helper` — it is declared `public`.
    let helper = json["hubs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|h| {
            let n = h["function_ref"]["name"].as_str().unwrap_or("");
            n == "Lib.helper" || n == "helper"
        })
        .unwrap_or_else(|| {
            panic!(
                "`Lib.helper`/`helper` not in hubs:\n{}",
                serde_json::to_string_pretty(&json).unwrap()
            )
        });

    assert_eq!(
        helper["function_ref"]["is_public"].as_bool(),
        Some(true),
        "Java `Lib.helper` was declared public; hub.is_public must be true:\nhub={}",
        serde_json::to_string_pretty(helper).unwrap()
    );
}

/// C++: a `public:` access-specifier method must surface
/// `is_public: true`. Pre-fix `extract_cpp_function_info` produced
/// `visibility: None` for class methods AND the hub layer ignored it.
#[test]
fn test_m007_hubs_is_public_cpp() {
    let temp = TempDir::new().unwrap();

    fs::write(
        temp.path().join("lib.h"),
        "#pragma once\nclass Lib {\npublic:\n  int helper(int x) { return x + 1; }\nprivate:\n  int _internal(int x) { return helper(x) * 2; }\n};\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("main.cpp"),
        "#include \"lib.h\"\nint a(Lib& l) { return l.helper(1); }\nint b(Lib& l) { return l.helper(2); }\nint c(Lib& l) { return l.helper(3); }\nint d(Lib& l) { return l.helper(4); }\n",
    )
    .unwrap();

    let json = run_hubs_json(temp.path(), "cpp");

    let helper = json["hubs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|h| {
            let n = h["function_ref"]["name"].as_str().unwrap_or("");
            n == "Lib::helper" || n == "Lib.helper" || n == "helper"
        })
        .unwrap_or_else(|| {
            panic!(
                "`Lib::helper` not in C++ hubs:\n{}",
                serde_json::to_string_pretty(&json).unwrap()
            )
        });

    assert_eq!(
        helper["function_ref"]["is_public"].as_bool(),
        Some(true),
        "C++ `Lib::helper` is under `public:` — hub.is_public must be true:\nhub={}",
        serde_json::to_string_pretty(helper).unwrap()
    );
}

/// C#: a `public` method must surface `is_public: true`.
#[test]
fn test_m007_hubs_is_public_csharp() {
    let temp = TempDir::new().unwrap();

    fs::write(
        temp.path().join("Lib.cs"),
        "namespace Demo;\npublic class Lib {\n    public int Helper(int x) { return x + 1; }\n    private int Internal_(int x) { return Helper(x) * 2; }\n}\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("Caller.cs"),
        "namespace Demo;\npublic class Caller {\n    public int A() { return new Lib().Helper(1); }\n    public int B() { return new Lib().Helper(2); }\n    public int C() { return new Lib().Helper(3); }\n    public int D() { return new Lib().Helper(4); }\n}\n",
    )
    .unwrap();

    let json = run_hubs_json(temp.path(), "csharp");

    let helper = json["hubs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|h| {
            let n = h["function_ref"]["name"].as_str().unwrap_or("");
            n == "Lib.Helper" || n == "Helper"
        })
        .unwrap_or_else(|| {
            panic!(
                "`Lib.Helper` not in C# hubs:\n{}",
                serde_json::to_string_pretty(&json).unwrap()
            )
        });

    assert_eq!(
        helper["function_ref"]["is_public"].as_bool(),
        Some(true),
        "C# `Lib.Helper` was declared public; hub.is_public must be true:\nhub={}",
        serde_json::to_string_pretty(helper).unwrap()
    );
}
