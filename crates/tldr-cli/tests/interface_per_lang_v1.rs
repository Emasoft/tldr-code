//! interface-per-lang-v1 (v0.4.2 M-022)
//!
//! Phase-22 audit cluster M-022 flagged that `tldr interface` misses
//! idiomatic public-API forms across many languages:
//!
//!   - c:          function prototypes in `.h` (declaration > function_declarator)
//!   - javascript: prototype-assignment exports (`Foo.prototype.bar = function()`,
//!                 `exports.X = ...`)
//!   - ocaml:      `.mli` val declarations (separate grammar)
//!   - swift:      methods inside `extension Foo { ... }` blocks
//!   - csharp:     `is_async:false` for every method (modifier child wiring gap)
//!   - rust:       `pub(crate)` types/functions surfaced as public
//!   - scala:      `private class Foo` surfaced as public
//!
//! This file pins per-language interface extraction at the integration
//! level (round-trip via `tldr interface --format json`). Fixtures are
//! small in-memory snippets so the tests don't depend on /tmp/repos.

use std::fs;
use std::path::{Path, PathBuf};
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

fn run_interface(file: &Path) -> serde_json::Value {
    let out = Command::new(tldr_bin())
        .args(["interface", file.to_str().unwrap(), "--format", "json"])
        .output()
        .expect("failed to run tldr interface");
    assert!(
        out.status.success(),
        "tldr interface failed for {}: {}",
        file.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "invalid JSON from interface {}: {}\n{}",
            file.display(),
            e,
            stdout
        )
    })
}

fn write_fixture(name: &str, content: &str) -> PathBuf {
    let dir = std::env::temp_dir().join("tldr_iface_per_lang_v1");
    let _ = fs::create_dir_all(&dir);
    let p = dir.join(name);
    fs::write(&p, content).expect("write fixture");
    p
}

fn func_names(v: &serde_json::Value) -> Vec<String> {
    v.get("functions")
        .and_then(|f| f.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|f| f.get("name").and_then(|n| n.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

fn class_method_names(v: &serde_json::Value, cname: &str) -> Vec<String> {
    let classes = match v.get("classes").and_then(|c| c.as_array()) {
        Some(arr) => arr,
        None => return Vec::new(),
    };
    // Union methods across every class entry whose name matches — Swift
    // extension blocks and Rust impl entries can produce multiple
    // ClassInfo records sharing the same name, each carrying a subset
    // of the methods. Treat them as a single logical class.
    let mut out = Vec::new();
    for c in classes {
        if c.get("name").and_then(|n| n.as_str()) == Some(cname) {
            if let Some(methods) = c.get("methods").and_then(|m| m.as_array()) {
                for m in methods {
                    if let Some(n) = m.get("name").and_then(|x| x.as_str()) {
                        out.push(n.to_string());
                    }
                }
            }
        }
    }
    out
}

fn class_method_async(v: &serde_json::Value, cname: &str, mname: &str) -> Option<bool> {
    let classes = v.get("classes")?.as_array()?;
    for c in classes {
        if c.get("name").and_then(|n| n.as_str()) != Some(cname) {
            continue;
        }
        if let Some(methods) = c.get("methods").and_then(|m| m.as_array()) {
            for m in methods {
                if m.get("name").and_then(|n| n.as_str()) == Some(mname) {
                    return m.get("is_async").and_then(|a| a.as_bool());
                }
            }
        }
    }
    None
}

fn class_names(v: &serde_json::Value) -> Vec<String> {
    v.get("classes")
        .and_then(|c| c.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|c| c.get("name").and_then(|n| n.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

// ============================================================================
// C — function prototypes in .h headers (declaration + function_declarator)
// ============================================================================
#[test]
fn c_header_prototypes_emitted_as_functions() {
    let src = "\
#ifndef SDS_H
#define SDS_H
typedef char *sds;
sds sdsnewlen(const void *init, size_t initlen);
sds sdsnew(const char *init);
sds sdsempty(void);
void sdsfree(sds s);
size_t sdslen(const sds s);
int sdscmp(const sds s1, const sds s2);
sds sdscat(sds s, const char *t);
static inline size_t sdsHdrSize(char type) { return 0; }
#endif
";
    let p = write_fixture("sds_iface.h", src);
    let v = run_interface(&p);
    let names = func_names(&v);
    // All 7 declarations should be visible. The `static inline` definition
    // is file-local and must be excluded.
    for needed in &[
        "sdsnewlen", "sdsnew", "sdsempty", "sdsfree", "sdslen", "sdscmp", "sdscat",
    ] {
        assert!(
            names.iter().any(|n| n == needed),
            "C prototype `{}` missing from interface output (got {:?})",
            needed,
            names
        );
    }
    assert!(
        !names.iter().any(|n| n == "sdsHdrSize"),
        "static inline `sdsHdrSize` should be filtered out (file-local), got {:?}",
        names
    );
}

// ============================================================================
// JavaScript — prototype assignments + module.exports
// ============================================================================
#[test]
fn javascript_prototype_assignments_emitted() {
    let src = "\
function Application() {
  this.name = \"app\";
}
Application.prototype.render = function(req, res) {
  return res.send(\"ok\");
};
Application.prototype.handle = function(req, res, next) {
  next();
};
exports.create = function() { return new Application(); };
module.exports = Application;
";
    let p = write_fixture("iface_app.js", src);
    let v = run_interface(&p);
    let names = func_names(&v);
    assert!(
        names.iter().any(|n| n == "Application"),
        "`Application` function-declaration missing (got {:?})",
        names
    );
    // The prototype method names should surface as either top-level
    // functions or as methods on `Application`. Accept either shape.
    let methods = class_method_names(&v, "Application");
    let has_render = names.iter().any(|n| n == "render")
        || methods.iter().any(|n| n == "render");
    let has_handle = names.iter().any(|n| n == "handle")
        || methods.iter().any(|n| n == "handle");
    let has_create = names.iter().any(|n| n == "create");
    assert!(
        has_render,
        "prototype assignment `Application.prototype.render` not surfaced (functions={:?}, methods={:?})",
        names, methods
    );
    assert!(
        has_handle,
        "prototype assignment `Application.prototype.handle` not surfaced (functions={:?}, methods={:?})",
        names, methods
    );
    assert!(
        has_create,
        "module-export assignment `exports.create` not surfaced (functions={:?})",
        names
    );
}

// ============================================================================
// OCaml — `.mli` val declarations (interface grammar)
// ============================================================================
#[test]
fn ocaml_mli_val_declarations_emitted() {
    let src = "\
val create : string -> int -> t
val update : t -> string -> t
val to_string : t -> string
type t
";
    let p = write_fixture("thing_iface.mli", src);
    let v = run_interface(&p);
    let names = func_names(&v);
    for needed in &["create", "update", "to_string"] {
        assert!(
            names.iter().any(|n| n == needed),
            "ocaml val-decl `{}` missing from interface output (got {:?})",
            needed,
            names
        );
    }
}

// ============================================================================
// Swift — methods defined inside extension blocks
// ============================================================================
#[test]
fn swift_extension_methods_collected() {
    let src = "\
public class Shape {
    public var name: String = \"\"
}

extension Shape {
    public func area() -> Double { return 0.0 }
    public func perimeter() -> Double { return 0.0 }
    public func describe() -> String { return self.name }
}
";
    let p = write_fixture("Shape_iface.swift", src);
    let v = run_interface(&p);
    // Methods may be attached to the Shape class entry or surfaced as
    // top-level functions; accept either to keep the test robust to the
    // walker convention swift settles on.
    let methods = class_method_names(&v, "Shape");
    let funcs = func_names(&v);
    for needed in &["area", "perimeter", "describe"] {
        let in_methods = methods.iter().any(|n| n == needed);
        let in_funcs = funcs.iter().any(|n| n == needed);
        assert!(
            in_methods || in_funcs,
            "swift extension method `{}` missing (methods={:?}, functions={:?})",
            needed,
            methods,
            funcs
        );
    }
}

// ============================================================================
// C# — is_async on async methods
// ============================================================================
#[test]
fn csharp_async_method_emits_is_async_true() {
    let src = "\
namespace App {
    public class Service {
        public async Task<int> FetchAsync() { return 1; }
        public Task DoIt() { return Task.CompletedTask; }
        public int Sync() { return 0; }
    }
}
";
    let p = write_fixture("Service_iface.cs", src);
    let v = run_interface(&p);
    assert_eq!(
        class_method_async(&v, "Service", "FetchAsync"),
        Some(true),
        "csharp async method should report is_async:true, got {:?}",
        v
    );
    assert_eq!(
        class_method_async(&v, "Service", "DoIt"),
        Some(false),
        "csharp Task-returning (non-async) method should report is_async:false"
    );
    assert_eq!(
        class_method_async(&v, "Service", "Sync"),
        Some(false),
        "csharp sync method should report is_async:false"
    );
}

// ============================================================================
// Rust — pub(crate) and private items excluded from public interface
// ============================================================================
#[test]
fn rust_pub_crate_excluded_from_interface() {
    let src = "\
pub fn public_fn() -> i32 { 1 }
fn private_fn() -> i32 { 2 }
pub(crate) fn crate_visible() -> i32 { 3 }

pub struct PublicStruct { pub field: i32 }
struct PrivateStruct { value: i32 }
pub(crate) struct CrateStruct;
";
    let p = write_fixture("rust_vis_iface.rs", src);
    let v = run_interface(&p);
    let funcs = func_names(&v);
    let classes = class_names(&v);
    assert!(
        funcs.iter().any(|n| n == "public_fn"),
        "rust `pub fn` missing (got {:?})",
        funcs
    );
    assert!(
        !funcs.iter().any(|n| n == "private_fn"),
        "rust private fn must be excluded (got {:?})",
        funcs
    );
    assert!(
        !funcs.iter().any(|n| n == "crate_visible"),
        "rust pub(crate) fn must be excluded from public interface (got {:?})",
        funcs
    );
    assert!(
        classes.iter().any(|n| n == "PublicStruct"),
        "rust `pub struct` missing (got {:?})",
        classes
    );
    assert!(
        !classes.iter().any(|n| n == "PrivateStruct"),
        "rust private struct must be excluded (got {:?})",
        classes
    );
    assert!(
        !classes.iter().any(|n| n == "CrateStruct"),
        "rust pub(crate) struct must be excluded (got {:?})",
        classes
    );
    let exports = v
        .get("all_exports")
        .and_then(|a| a.as_array())
        .cloned()
        .unwrap_or_default();
    let export_names: Vec<String> = exports
        .iter()
        .filter_map(|e| e.as_str().map(String::from))
        .collect();
    assert!(
        !export_names.iter().any(|n| n == "CrateStruct" || n == "crate_visible"),
        "all_exports must exclude pub(crate) items, got {:?}",
        export_names
    );
}

// ============================================================================
// Scala — private classes/methods excluded
// ============================================================================
#[test]
fn scala_private_class_and_method_excluded() {
    let src = "\
package app

class Service {
  def publicMethod(x: Int): Int = x + 1
  private def privateHelper(): Unit = ()
  def anotherPub(): String = \"hi\"
}

private class SyncStep {
  def run(): Unit = ()
}
";
    let p = write_fixture("Stuff_iface.scala", src);
    let v = run_interface(&p);
    let classes = class_names(&v);
    assert!(
        classes.iter().any(|n| n == "Service"),
        "scala `class Service` missing (got {:?})",
        classes
    );
    assert!(
        !classes.iter().any(|n| n == "SyncStep"),
        "scala `private class SyncStep` must be excluded (got {:?})",
        classes
    );
    let svc_methods = class_method_names(&v, "Service");
    assert!(
        svc_methods.iter().any(|n| n == "publicMethod"),
        "scala public def missing (got {:?})",
        svc_methods
    );
    assert!(
        svc_methods.iter().any(|n| n == "anotherPub"),
        "scala public def `anotherPub` missing (got {:?})",
        svc_methods
    );
    assert!(
        !svc_methods.iter().any(|n| n == "privateHelper"),
        "scala `private def` must be excluded from methods (got {:?})",
        svc_methods
    );
}

// ============================================================================
// Bonus: ensure C-style header empty input still returns a sane shape
// ============================================================================
#[test]
fn c_header_empty_input_returns_empty_arrays() {
    let src = "/* empty header */\n#ifndef X\n#define X\n#endif\n";
    let p = write_fixture("empty_iface.h", src);
    let v = run_interface(&p);
    assert!(v.get("functions").and_then(|f| f.as_array()).is_some());
    assert!(v.get("classes").and_then(|c| c.as_array()).is_some());
}
