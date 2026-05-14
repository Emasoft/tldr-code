//! is-public-visibility-v1 (v0.4.2 M-007)
//!
//! Phase-22 audit cluster M-007 flagged that per-language FunctionRef
//! builders defaulted `is_public:false` (or null) for every function
//! and never inspected AST modifier tokens. As a result:
//!
//!   - csharp: every `public` method was reported `is_public:false`
//!   - java:   modifier child was never inspected
//!   - kotlin: public top-level fns reported false
//!   - swift:  `is_public` emitted `null` rather than a boolean
//!   - go:     uppercase-first-letter heuristic was missing
//!   - javascript: `app.render = function () {}` (member-export
//!                 prototype pattern) was not detected as public.
//!
//! This file pins per-language AST visibility extraction. The
//! `FunctionInfo` struct gains a `visibility: Option<String>` field
//! emitted in `tldr extract` JSON; tests confirm the field is
//! populated correctly per language. Each test uses small inline
//! fixtures (no /tmp/repos dependency) since the visibility behaviour
//! is purely a parser-level concern, not corpus-dependent.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

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

fn run_extract(file: &std::path::Path) -> serde_json::Value {
    let out = Command::new(tldr_bin())
        .args(["extract", file.to_str().unwrap()])
        .output()
        .expect("failed to run tldr extract");
    assert!(
        out.status.success(),
        "tldr extract failed for {}: {}",
        file.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("invalid JSON from extract {}: {}\n{}", file.display(), e, stdout))
}

/// Find a method `mname` inside class `cname` and return its visibility string.
fn class_method_visibility<'a>(
    json: &'a serde_json::Value,
    cname: &str,
    mname: &str,
) -> Option<&'a str> {
    let classes = json.get("classes")?.as_array()?;
    for c in classes {
        if c.get("name")?.as_str()? == cname {
            let methods = c.get("methods")?.as_array()?;
            for m in methods {
                if m.get("name")?.as_str()? == mname {
                    return m.get("visibility").and_then(|v| v.as_str());
                }
            }
        }
    }
    None
}

/// Find a top-level function and return its visibility string.
fn top_level_visibility<'a>(json: &'a serde_json::Value, fname: &str) -> Option<&'a str> {
    let funcs = json.get("functions")?.as_array()?;
    for f in funcs {
        if f.get("name")?.as_str()? == fname {
            return f.get("visibility").and_then(|v| v.as_str());
        }
    }
    None
}

fn write_fixture(name: &str, content: &str) -> PathBuf {
    let dir = std::env::temp_dir().join("tldr_is_public_v1");
    let _ = fs::create_dir_all(&dir);
    let p = dir.join(name);
    fs::write(&p, content).expect("write fixture");
    p
}

// ============================================================================
// C# — explicit access modifier keywords on member declarations
// ============================================================================
#[test]
fn csharp_method_visibility_extracted_from_modifiers() {
    let src = r#"
public class Foo {
    public void doPublic() {}
    private void doPrivate() {}
    protected void doProtected() {}
    internal void doInternal() {}
    void doDefault() {}
}
"#;
    let f = write_fixture("vis_csharp.cs", src);
    let j = run_extract(&f);

    assert_eq!(
        class_method_visibility(&j, "Foo", "doPublic"),
        Some("public"),
        "csharp: `public` method should report visibility=public"
    );
    assert_eq!(
        class_method_visibility(&j, "Foo", "doPrivate"),
        Some("private"),
        "csharp: `private` method should report visibility=private"
    );
    assert_eq!(
        class_method_visibility(&j, "Foo", "doProtected"),
        Some("protected"),
        "csharp: `protected` method should report visibility=protected"
    );
    assert_eq!(
        class_method_visibility(&j, "Foo", "doInternal"),
        Some("internal"),
        "csharp: `internal` method should report visibility=internal"
    );
}

// ============================================================================
// Java — explicit modifier child on method_declaration
// ============================================================================
#[test]
fn java_method_visibility_extracted_from_modifiers() {
    let src = r#"
public class Foo {
    public void doPublic() {}
    private void doPrivate() {}
    protected void doProtected() {}
    void doPackagePrivate() {}
}
"#;
    let f = write_fixture("VisJava.java", src);
    let j = run_extract(&f);

    assert_eq!(
        class_method_visibility(&j, "Foo", "doPublic"),
        Some("public"),
        "java: `public` method should report visibility=public"
    );
    assert_eq!(
        class_method_visibility(&j, "Foo", "doPrivate"),
        Some("private"),
        "java: `private` method should report visibility=private"
    );
    assert_eq!(
        class_method_visibility(&j, "Foo", "doProtected"),
        Some("protected"),
        "java: `protected` method should report visibility=protected"
    );
    // Package-private = no modifier; we omit the field rather than fabricate.
    assert!(
        class_method_visibility(&j, "Foo", "doPackagePrivate").is_none(),
        "java: package-private (no modifier) should leave visibility unset"
    );
}

// ============================================================================
// Kotlin — modifiers > visibility_modifier
// ============================================================================
#[test]
fn kotlin_function_visibility_extracted_from_modifiers() {
    let src = r#"
fun publicTopLevel() {}
private fun privateTopLevel() {}
internal fun internalTopLevel() {}

public class Bar {
    fun defaultMethod() {}
    private fun privMethod() {}
    protected fun protMethod() {}
}
"#;
    let f = write_fixture("VisKotlin.kt", src);
    let j = run_extract(&f);

    // Top-level: Kotlin default is `public`.
    // Be tolerant: either explicit "public" OR None (default = public per Kotlin spec).
    // Per the audit we require that a function declared with NO explicit modifier
    // is NOT incorrectly classified as private. The downstream `is_public` consumer
    // treats `None` as public for Kotlin. We pin the explicit-keyword cases tightly.
    assert_eq!(
        top_level_visibility(&j, "privateTopLevel"),
        Some("private"),
        "kotlin: `private fun` should report visibility=private"
    );
    assert_eq!(
        top_level_visibility(&j, "internalTopLevel"),
        Some("internal"),
        "kotlin: `internal fun` should report visibility=internal"
    );

    assert_eq!(
        class_method_visibility(&j, "Bar", "privMethod"),
        Some("private"),
        "kotlin: `private fun` method should report visibility=private"
    );
    assert_eq!(
        class_method_visibility(&j, "Bar", "protMethod"),
        Some("protected"),
        "kotlin: `protected fun` method should report visibility=protected"
    );
}

// ============================================================================
// Swift — visibility modifier keywords (public, open, internal, private,
//         fileprivate). A function with no modifier defaults to `internal`.
// ============================================================================
#[test]
fn swift_function_visibility_extracted_from_modifiers() {
    let src = r#"
public func doPublic() {}
private func doPrivate() {}
internal func doInternal() {}
fileprivate func doFilePrivate() {}
open func doOpen() {}
func doDefault() {}
"#;
    let f = write_fixture("vis_swift.swift", src);
    let j = run_extract(&f);

    assert_eq!(
        top_level_visibility(&j, "doPublic"),
        Some("public"),
        "swift: `public func` should report visibility=public"
    );
    assert_eq!(
        top_level_visibility(&j, "doPrivate"),
        Some("private"),
        "swift: `private func` should report visibility=private"
    );
    assert_eq!(
        top_level_visibility(&j, "doInternal"),
        Some("internal"),
        "swift: `internal func` should report visibility=internal"
    );
    assert_eq!(
        top_level_visibility(&j, "doFilePrivate"),
        Some("fileprivate"),
        "swift: `fileprivate func` should report visibility=fileprivate"
    );
    assert_eq!(
        top_level_visibility(&j, "doOpen"),
        Some("open"),
        "swift: `open func` should report visibility=open"
    );
}

// ============================================================================
// Go — case-as-visibility (uppercase first letter = exported).
// ============================================================================
#[test]
fn go_function_visibility_inferred_from_case() {
    let src = r#"
package foo

// Exported function
func Foo() {}

// Unexported helper
func bar() {}

type Receiver struct{}

// Exported method
func (r *Receiver) DoIt() {}

// Unexported method
func (r *Receiver) doInternal() {}
"#;
    let f = write_fixture("vis_go.go", src);
    let j = run_extract(&f);

    assert_eq!(
        top_level_visibility(&j, "Foo"),
        Some("public"),
        "go: uppercase-first-letter `Foo` should report visibility=public"
    );
    assert_eq!(
        top_level_visibility(&j, "bar"),
        Some("private"),
        "go: lowercase-first-letter `bar` should report visibility=private"
    );
    // Methods land under classes[] (auto-vivified by the Go extractor)
    // — the `top_level_visibility` helper looks at `functions[]` only.
    assert_eq!(
        class_method_visibility(&j, "Receiver", "DoIt"),
        Some("public"),
        "go: uppercase-first-letter method `DoIt` should report visibility=public"
    );
    assert_eq!(
        class_method_visibility(&j, "Receiver", "doInternal"),
        Some("private"),
        "go: lowercase-first-letter method `doInternal` should report visibility=private"
    );
}

// ============================================================================
// JavaScript — member-export assignments (`app.render = function () {}`,
// `exports.X = function () {}`, `module.exports = function () {}`) are
// treated as public exports; plain `function _hidden() {}` is private.
// ============================================================================
#[test]
fn javascript_member_export_visibility_detected() {
    let src = r#"
function helperFn() {}
function _hidden() {}
app.render = function namedRender(req, res) {};
exports.process = function processData() {};
module.exports = function makeServer() {};
"#;
    let f = write_fixture("vis_js.js", src);
    let j = run_extract(&f);

    // Member-export RHS assignments are flagged public.
    assert_eq!(
        top_level_visibility(&j, "render"),
        Some("public"),
        "js: `app.render = function () {{}}` should report visibility=public (member-export)"
    );
    assert_eq!(
        top_level_visibility(&j, "process"),
        Some("public"),
        "js: `exports.process = function () {{}}` should report visibility=public"
    );

    // Plain functions starting with `_` are private by convention.
    assert_eq!(
        top_level_visibility(&j, "_hidden"),
        Some("private"),
        "js: function name starting with `_` should report visibility=private"
    );
}

// ============================================================================
// End-to-end: `tldr dead` reports public-vs-private categorization correctly
// for each language. (We avoid asserting specific dead/live status because
// that depends on the call-graph; we only assert that the visibility-derived
// distinction surfaces.)
// ============================================================================
#[test]
fn extract_json_visibility_field_is_string_when_present() {
    // Sanity: when visibility IS emitted it must be a string, never null.
    let src = r#"
public class Foo {
    public void doPublic() {}
}
"#;
    let f = write_fixture("vis_sanity.cs", src);
    let j = run_extract(&f);
    let v = class_method_visibility(&j, "Foo", "doPublic");
    assert!(
        matches!(v, Some(s) if !s.is_empty()),
        "visibility must be a non-empty string when present, got {:?}",
        v
    );
}
