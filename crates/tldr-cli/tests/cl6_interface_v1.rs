//! cl6_interface_v1 (v0.5.0 CL-6, GH #78):
//!
//! Pre-fix audit assertion (iter-3 fix wave, CL-6):
//! > "interface command inferior extractor. The `visit_top_level` walker
//! >  only iterates *direct children* of the file root and recurses for
//! >  PHP only. It misses:
//! >    * export-wrapped classes/functions (TS/JS `export class Foo`),
//! >    * package-block-nested definitions (Scala `package p { class C }`),
//! >    * nested classes (Ruby `class Outer; class Inner; end; end`),
//! >    * qualified / operator / destructor C++ member names
//! >      (`operator[]`, `~StrPair`, `Foo::method`)."
//!
//! Verdict: REAL BUG. Verified pre-fix against the corpora and the release
//! binary:
//!   * `tldr interface application-config.ts` reported ZERO classes even
//!     though the file declares `export class ApplicationConfig { ... }`
//!     with ~30 public methods (`tldr structure` lists it).
//!   * `tldr interface tinyxml2.h` dropped every C++ `operator` and
//!     `~Destructor` member (`DynArray::operator[]`, `StrPair::~StrPair`).
//!   * A `package p { class C }` Scala block yielded zero classes.
//!   * A Ruby `class Outer; class Inner; end; end` surfaced only `Outer`.
//!
//! Fix (this v1, AST-DRIVEN):
//!   * `visit_top_level` descends through wrapper nodes that contain class /
//!     function definitions but are not themselves classes/functions:
//!     `export_statement` (TS/JS), Scala `package_clause` block bodies, and
//!     class bodies (so nested classes surface). Decorated export classes
//!     (`@Controller() export class Foo`) are handled by peeling the
//!     `export_statement` then the `decorator` siblings.
//!   * `extract_c_declarator_name` resolves `destructor_name`,
//!     `operator_name`, and `qualified_identifier` / `scoped_identifier`
//!     leaves (matching the canonical handling in
//!     `tldr-core::analysis::references::find_cpp_declarator_match`).
//!
//! Real-repo gated against /tmp/tldr_corpora/<lang> and the release binary;
//! corpus-backed tests skip with a printed reason when the corpus is not
//! present (matching the pattern used elsewhere in this suite). Synthetic
//! fixtures (valid real-world source forms) are written to a temp dir for
//! the patterns that are sparse in the pinned corpora.

use std::path::{Path, PathBuf};
use std::process::Command;

const TS_APP_CONFIG: &str =
    "/tmp/tldr_corpora/typescript-nest/packages/core/application-config.ts";
const TS_APP_CONTROLLER: &str =
    "/tmp/tldr_corpora/typescript-nest/tools/benchmarks/src/frameworks/nest/app.controller.ts";
const CPP_TINYXML2: &str = "/tmp/tldr_corpora/cpp-tinyxml2/tinyxml2.h";
const SCALA_EXITCODE: &str =
    "/tmp/tldr_corpora/scala-cats-effect/core/shared/src/main/scala/cats/effect/ExitCode.scala";

fn tldr_bin() -> PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR must be set under cargo test");
    PathBuf::from(manifest)
        .join("..")
        .join("..")
        .join("target")
        .join("release")
        .join("tldr")
}

fn run_tldr(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(tldr_bin())
        .args(args)
        .output()
        .expect("failed to run tldr binary");
    let exit = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    (exit, stdout, stderr)
}

/// Parse `tldr interface <file> --format json` into the class/method shape.
/// Returns `(classes, top_level_functions)` where `classes` is a list of
/// `(class_name, [method_names])` and `top_level_functions` is `[name]`.
#[allow(clippy::type_complexity)]
fn interface_of(file: &str) -> Option<(Vec<(String, Vec<String>)>, Vec<String>)> {
    let (rc, stdout, stderr) = run_tldr(&["interface", file, "--format", "json", "-q"]);
    if rc != 0 {
        eprintln!("tldr interface {file} exited {rc}: {stderr}");
        return None;
    }
    let v: serde_json::Value = serde_json::from_str(&stdout).ok()?;
    let classes = v
        .get("classes")?
        .as_array()?
        .iter()
        .map(|c| {
            let name = c
                .get("name")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let methods = c
                .get("methods")
                .and_then(|x| x.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|m| {
                            m.get("name").and_then(|x| x.as_str()).map(|s| s.to_string())
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            (name, methods)
        })
        .collect::<Vec<_>>();
    let functions = v
        .get("functions")?
        .as_array()?
        .iter()
        .filter_map(|f| f.get("name").and_then(|x| x.as_str()).map(|s| s.to_string()))
        .collect::<Vec<_>>();
    Some((classes, functions))
}

fn class_names(classes: &[(String, Vec<String>)]) -> Vec<String> {
    classes.iter().map(|(n, _)| n.clone()).collect()
}

fn methods_of<'a>(
    classes: &'a [(String, Vec<String>)],
    class_name: &str,
) -> Option<&'a Vec<String>> {
    classes.iter().find(|(n, _)| n == class_name).map(|(_, m)| m)
}

/// Write `content` to `dir/name` and return the absolute path string.
fn write_fixture(dir: &Path, name: &str, content: &str) -> String {
    let p = dir.join(name);
    std::fs::write(&p, content).expect("write fixture");
    p.to_string_lossy().into_owned()
}

// ==========================================================================
// TypeScript: export-wrapped classes / functions
// ==========================================================================

#[test]
fn cl6_ts_export_class_surfaces_in_real_corpus() {
    if !Path::new(TS_APP_CONFIG).exists() {
        eprintln!("SKIP: {TS_APP_CONFIG} not present");
        return;
    }
    let (classes, _funcs) =
        interface_of(TS_APP_CONFIG).expect("interface JSON for application-config.ts");
    let names = class_names(&classes);
    assert!(
        names.iter().any(|n| n == "ApplicationConfig"),
        "export class ApplicationConfig must surface in `tldr interface`; got classes {names:?}"
    );
    let methods = methods_of(&classes, "ApplicationConfig")
        .expect("ApplicationConfig class entry must exist");
    // The class declares many public methods (setGlobalPrefix, getIoAdapter,
    // useGlobalPipes, ...). Pre-fix the class was entirely absent so methods
    // were []. Require the export-wrapped class to carry its real method set.
    assert!(
        methods.iter().any(|m| m == "setGlobalPrefix"),
        "ApplicationConfig.setGlobalPrefix must be enumerated; got methods {methods:?}"
    );
    assert!(
        methods.len() >= 10,
        "ApplicationConfig should expose its full public method surface (>=10); got {} ({methods:?})",
        methods.len()
    );
}

#[test]
fn cl6_ts_decorated_export_class_surfaces_in_real_corpus() {
    if !Path::new(TS_APP_CONTROLLER).exists() {
        eprintln!("SKIP: {TS_APP_CONTROLLER} not present");
        return;
    }
    let (classes, _funcs) =
        interface_of(TS_APP_CONTROLLER).expect("interface JSON for app.controller.ts");
    let names = class_names(&classes);
    // `@Controller('/') export class AppController { @Get() root() {} }`
    assert!(
        names.iter().any(|n| n == "AppController"),
        "decorated `export class AppController` must surface; got classes {names:?}"
    );
    let methods =
        methods_of(&classes, "AppController").expect("AppController class entry must exist");
    assert!(
        methods.iter().any(|m| m == "root"),
        "AppController.root() must be enumerated; got methods {methods:?}"
    );
}

#[test]
fn cl6_ts_export_function_and_default_class_surface() {
    let dir = std::env::temp_dir().join("cl6_ts_fixtures");
    std::fs::create_dir_all(&dir).expect("mkdir fixtures");
    let file = write_fixture(
        &dir,
        "exports.ts",
        r#"export class Widget {
  render(): string { return "<div/>"; }
  resize(w: number, h: number): void {}
}

export function makeWidget(label: string): Widget {
  return new Widget();
}

export default class DefaultThing {
  go(): void {}
}
"#,
    );
    let (classes, funcs) = interface_of(&file).expect("interface JSON for exports.ts");
    let names = class_names(&classes);
    assert!(
        names.iter().any(|n| n == "Widget"),
        "`export class Widget` must surface; got {names:?}"
    );
    assert!(
        names.iter().any(|n| n == "DefaultThing"),
        "`export default class DefaultThing` must surface; got {names:?}"
    );
    assert!(
        funcs.iter().any(|f| f == "makeWidget"),
        "`export function makeWidget` must surface in functions[]; got {funcs:?}"
    );
    let widget_methods = methods_of(&classes, "Widget").expect("Widget entry");
    assert!(
        widget_methods.iter().any(|m| m == "render")
            && widget_methods.iter().any(|m| m == "resize"),
        "Widget methods must include render+resize; got {widget_methods:?}"
    );
}

// ==========================================================================
// Scala: package-block-nested definitions
// ==========================================================================

#[test]
fn cl6_scala_package_block_nested_classes_surface() {
    let dir = std::env::temp_dir().join("cl6_scala_fixtures");
    std::fs::create_dir_all(&dir).expect("mkdir fixtures");
    let file = write_fixture(
        &dir,
        "pkgblock.scala",
        r#"package com.example {
  class Foo {
    def bar(x: Int): Int = x
    def baz(): String = "hi"
  }
  object Qux {
    def run(): Unit = ()
  }
}
"#,
    );
    let (classes, _funcs) = interface_of(&file).expect("interface JSON for pkgblock.scala");
    let names = class_names(&classes);
    assert!(
        names.iter().any(|n| n == "Foo"),
        "class Foo nested in `package com.example {{ ... }}` must surface; got {names:?}"
    );
    assert!(
        names.iter().any(|n| n == "Qux"),
        "object Qux nested in a package block must surface; got {names:?}"
    );
    let foo_methods = methods_of(&classes, "Foo").expect("Foo entry");
    assert!(
        foo_methods.iter().any(|m| m == "bar") && foo_methods.iter().any(|m| m == "baz"),
        "Foo methods must include bar+baz; got {foo_methods:?}"
    );
}

#[test]
fn cl6_scala_file_level_package_regression_guard() {
    // Regression guard: file-level `package cats.effect` (a package_clause,
    // not a block) already worked pre-fix — the fix must not regress it.
    if !Path::new(SCALA_EXITCODE).exists() {
        eprintln!("SKIP: {SCALA_EXITCODE} not present");
        return;
    }
    let (classes, _funcs) = interface_of(SCALA_EXITCODE).expect("interface JSON for ExitCode.scala");
    let names = class_names(&classes);
    assert!(
        names.iter().any(|n| n == "ExitCode"),
        "file-level package `ExitCode` must still surface after fix; got {names:?}"
    );
}

// ==========================================================================
// Ruby: nested classes
// ==========================================================================

#[test]
fn cl6_ruby_nested_class_surfaces() {
    let dir = std::env::temp_dir().join("cl6_ruby_fixtures");
    std::fs::create_dir_all(&dir).expect("mkdir fixtures");
    let file = write_fixture(
        &dir,
        "nested.rb",
        r#"class Outer
  def outer_method
  end

  class Inner
    def inner_method
    end
  end

  module Mixin
    def mixin_method
    end
  end
end
"#,
    );
    let (classes, _funcs) = interface_of(&file).expect("interface JSON for nested.rb");
    let names = class_names(&classes);
    assert!(
        names.iter().any(|n| n == "Outer"),
        "Outer must surface; got {names:?}"
    );
    assert!(
        names.iter().any(|n| n == "Inner"),
        "nested `class Inner` must surface; got {names:?}"
    );
    let inner_methods = methods_of(&classes, "Inner").expect("Inner entry");
    assert!(
        inner_methods.iter().any(|m| m == "inner_method"),
        "Inner.inner_method must be enumerated; got {inner_methods:?}"
    );
}

// ==========================================================================
// C++: operator / destructor / qualified member names
// ==========================================================================

#[test]
fn cl6_cpp_operator_and_destructor_names_surface() {
    if !Path::new(CPP_TINYXML2).exists() {
        eprintln!("SKIP: {CPP_TINYXML2} not present");
        return;
    }
    let (classes, _funcs) = interface_of(CPP_TINYXML2).expect("interface JSON for tinyxml2.h");

    // DynArray declares a public `T& operator[](size_t i)`.
    let dynarray = methods_of(&classes, "DynArray")
        .expect("DynArray class entry must exist in tinyxml2.h interface");
    assert!(
        dynarray.iter().any(|m| m == "operator[]"),
        "DynArray::operator[] must be enumerated as a member; got {dynarray:?}"
    );

    // StrPair declares a public destructor `~StrPair()`.
    let strpair = methods_of(&classes, "StrPair")
        .expect("StrPair class entry must exist in tinyxml2.h interface");
    assert!(
        strpair.iter().any(|m| m == "~StrPair"),
        "StrPair::~StrPair destructor must be enumerated as a member; got {strpair:?}"
    );
}

#[test]
fn cl6_cpp_operator_destructor_qualified_synthetic() {
    let dir = std::env::temp_dir().join("cl6_cpp_fixtures");
    std::fs::create_dir_all(&dir).expect("mkdir fixtures");
    // A sibling `.cpp` forces C++ (not C) language detection for the header,
    // matching how `tinyxml2.h` is detected next to `tinyxml2.cpp`. Without a
    // sibling, a lone `.h` is parsed as C — where `~`/`operator`/`T&` are not
    // valid syntax — which is a separate language-detection concern, not the
    // CL-6 declarator-name bug under test.
    let _cpp_sibling = write_fixture(&dir, "shapes.cpp", "#include \"shapes.h\"\n");
    let file = write_fixture(
        &dir,
        "shapes.h",
        r#"class Vec {
public:
    Vec();
    ~Vec();
    Vec& operator=(const Vec& other);
    Vec& operator[](int i) { return *this; }
    void normalize();
};
"#,
    );
    let (classes, _funcs) = interface_of(&file).expect("interface JSON for shapes.h");
    let vec = methods_of(&classes, "Vec").expect("Vec class entry must exist");
    for expected in ["Vec", "~Vec", "operator=", "operator[]", "normalize"] {
        assert!(
            vec.iter().any(|m| m == expected),
            "Vec must enumerate member `{expected}`; got {vec:?}"
        );
    }
}
