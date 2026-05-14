//! reaching-defs-imports-params-globals-v1 (v0.4.2 cluster M-032):
//!
//! Pre-fix audit assertion (Phase-22 iter-1 M-032):
//! > "`tldr reaching-defs <file> <function>` flags imports, globals, type
//! >  references, method names on dotted access, hoisted function decls, and
//! >  (Luau only) function parameters as uninitialized variable uses.
//! >  Affects csharp (36 FPs), javascript (3), lua (3), luau (9), ocaml (13),
//! >  typescript (731 FPs in ts-dom-gen / emitWebIdl)."
//!
//! Verdict: REAL BUG. The identifier-vs-variable classifier in
//! `crates/tldr-core/src/dfg/extractor.rs` does not:
//!   - bind tree-sitter-luau `parameter` (wrapped) nodes as block-0 defs;
//!   - exclude TS/JS `import_statement` simple names from the use set;
//!   - exclude TS/JS `member_expression.property` (method/property names);
//!   - exclude C# `member_access_expression.name` (enum-member / method name);
//!   - exclude OCaml `value_path` `value_name` segments (module-qualified
//!     references like `Io.read_file`);
//!   - exclude Lua/Luau `field.name` (table-constructor keys like `cache`)
//!     or `dot_index_expression.field` (member accesses like `m.onWatch`);
//!   - recognize well-known globals (`Array`/`Error` JS, `print`/`assert`
//!     Lua/Luau).
//!
//! Fix v1 (per-lang AST classification, never regex):
//!   - Extend `DfgBuilder::collect_imports` to TS/JS/Lua/Luau/OCaml.
//!   - Extend `DfgBuilder::extract_lua_param` to recurse into `parameter`
//!     nodes (Luau wraps params; `tree-sitter-lua` did not).
//!   - Extend `is_use_context` to filter member-access property names for
//!     TS/JS/C#, OCaml module-qualified `value_path`, Lua/Luau field keys.
//!   - Bind built-in globals as defined for JS/Lua/Luau so they never
//!     flow into the uninit detector.
//!
//! Tests are real-repo gated for the dogfood cases and use synthetic
//! fixtures (tempfile) for the language-agnostic invariants so the suite
//! works offline.

use std::path::Path;
use std::process::Command;

const TS_DOM_CORPUS: &str = "/tmp/repos/ts-dom-gen/src/build/emitter.ts";
const LUA_LSP_CORPUS: &str = "/tmp/repos/lua-lsp/script/files.lua";
const LUAU_CORPUS: &str = "/tmp/repos/luau-luau/tests/conformance/tables.luau";
const CSHARP_BSON_CORPUS: &str =
    "/tmp/repos/csharp-newtonsoft-bson-full/Src/Newtonsoft.Json.Bson/BsonDataReader.Async.cs";
const JS_EXPRESS_CORPUS: &str = "/tmp/repos/express/lib/application.js";
const OCAML_DUNE_CORPUS: &str = "/tmp/repos/ocaml-dune/src/dune_rules/cram/cram_exec.ml";

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

fn uninit_vars(v: &serde_json::Value) -> Vec<String> {
    v.get("uninitialized")
        .and_then(|x| x.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|item| item.get("var").and_then(|s| s.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

fn write_tmp(name: &str, body: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("reaching_defs_m032_{}", name));
    std::fs::write(&p, body).expect("failed to write temp source");
    p
}

// =============================================================================
// SYNTHETIC FIXTURES (run offline, no /tmp/repos dependency)
// =============================================================================

/// TypeScript: imports and member-expression property names must never
/// be flagged as uninitialized variable uses.
#[test]
fn ts_imports_and_member_method_names_not_uninit() {
    let src = r#"import { helper, util } from "./mod.ts";
import * as Ns from "./ns.ts";

export function foo(x: number): number {
    const a = helper(x);
    const b = util.compute(a);
    const c = Ns.frob(b);
    return obj.method(c);
}
"#;
    let path = write_tmp("ts_imports.ts", src);
    let (code, stdout, stderr) =
        run_tldr(&["reaching-defs", path.to_str().unwrap(), "foo", "--format", "json"]);
    assert_eq!(code, 0, "tldr reaching-defs failed: {} {}", stdout, stderr);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("not valid json");
    let names = uninit_vars(&v);
    for forbidden in &["helper", "util", "Ns", "compute", "frob", "method"] {
        assert!(
            !names.iter().any(|n| n == forbidden),
            "TS: '{}' should not be flagged as uninitialized. Got: {:?}",
            forbidden,
            names
        );
    }
}

/// JavaScript: well-known globals (Array, Error) and hoisted function
/// declarations in the same file must not be uninit.
#[test]
fn js_globals_and_hoisted_funcs_not_uninit() {
    let src = r#"function caller(name, opts) {
    if (!opts.path) {
        var dirs = Array.isArray(opts.root) ? opts.root.join(",") : opts.root;
        var err = new Error("Failed to look up " + name);
        return err;
    }
    tryRender(name, opts);
}

function tryRender(view, options) {
    return view + options;
}
"#;
    let path = write_tmp("js_globals.js", src);
    let (code, stdout, stderr) =
        run_tldr(&["reaching-defs", path.to_str().unwrap(), "caller", "--format", "json"]);
    assert_eq!(code, 0, "tldr reaching-defs failed: {} {}", stdout, stderr);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("not valid json");
    let names = uninit_vars(&v);
    for forbidden in &["Array", "Error", "tryRender"] {
        assert!(
            !names.iter().any(|n| n == forbidden),
            "JS: '{}' should not be flagged as uninitialized. Got: {:?}",
            forbidden,
            names
        );
    }
}

/// C#: enum-member access (`State.Foo`) and method names on `obj.Method()`
/// must not be flagged as uninitialized.
#[test]
fn csharp_enum_members_and_method_names_not_uninit() {
    let src = r#"using System;

namespace TestNs {
    public enum State { Normal, Started, Ended }

    public class Reader {
        private State _state;

        public Task<bool> Read(int token) {
            Task<bool> t;
            switch (_state) {
                case State.Normal:
                    t = ReadNormal(token);
                    break;
                case State.Started:
                    t = ReadStarted(token);
                    break;
                default:
                    t = ReadDefault(token);
                    break;
            }
            return t;
        }

        private Task<bool> ReadNormal(int t) { return null; }
        private Task<bool> ReadStarted(int t) { return null; }
        private Task<bool> ReadDefault(int t) { return null; }
    }
}
"#;
    let path = write_tmp("cs_method_enum.cs", src);
    let (code, stdout, stderr) =
        run_tldr(&["reaching-defs", path.to_str().unwrap(), "Read", "--format", "json"]);
    assert_eq!(code, 0, "tldr reaching-defs failed: {} {}", stdout, stderr);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("not valid json");
    let names = uninit_vars(&v);
    for forbidden in &[
        "Normal",
        "Started",
        "Ended",
        "ReadNormal",
        "ReadStarted",
        "ReadDefault",
    ] {
        assert!(
            !names.iter().any(|n| n == forbidden),
            "C#: '{}' should not be flagged as uninitialized. Got: {:?}",
            forbidden,
            names
        );
    }
}

/// Lua: well-known globals (`print`, `assert`) and table-constructor
/// field keys (`cache`) must not be uninit. Method receivers via
/// `m.method()` should also be excluded when the receiver is a
/// file-level local.
#[test]
fn lua_globals_and_table_fields_not_uninit() {
    let src = r#"local m = {}

function m.open(uri)
    m.openMap = {
        cache = {},
    }
    m.onWatch('open', uri)
    print(uri)
    assert(uri ~= nil)
end
"#;
    let path = write_tmp("lua_table_fields.lua", src);
    let (code, stdout, stderr) =
        run_tldr(&["reaching-defs", path.to_str().unwrap(), "m.open", "--format", "json"]);
    assert_eq!(code, 0, "tldr reaching-defs failed: {} {}", stdout, stderr);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("not valid json");
    let names = uninit_vars(&v);
    for forbidden in &["cache", "print", "assert", "onWatch", "m"] {
        assert!(
            !names.iter().any(|n| n == forbidden),
            "Lua: '{}' should not be flagged as uninitialized. Got: {:?}",
            forbidden,
            names
        );
    }
}

/// Luau: function parameters must be detected as block-0 definitions.
/// The pre-fix `extract_lua_param` only handled bare `identifier` children
/// of `parameters`; tree-sitter-luau wraps each parameter in a
/// `parameter` node, so `t`, `na`, `nh` were silently dropped.
#[test]
fn luau_function_params_not_uninit() {
    let src = r#"local function check (t, na, nh)
    local a, h = T.querytab(t)
    if a ~= na or h ~= nh then
        print(na, nh, a, h)
        assert(nil)
    end
end
"#;
    let path = write_tmp("luau_params.luau", src);
    let (code, stdout, stderr) =
        run_tldr(&["reaching-defs", path.to_str().unwrap(), "check", "--format", "json"]);
    assert_eq!(code, 0, "tldr reaching-defs failed: {} {}", stdout, stderr);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("not valid json");
    let names = uninit_vars(&v);
    for forbidden in &["t", "na", "nh"] {
        assert!(
            !names.iter().any(|n| n == forbidden),
            "Luau: param '{}' should not be flagged as uninitialized. Got: {:?}",
            forbidden,
            names
        );
    }
    // Built-in globals also excluded:
    for forbidden in &["print", "assert"] {
        assert!(
            !names.iter().any(|n| n == forbidden),
            "Luau: global '{}' should not be flagged as uninitialized. Got: {:?}",
            forbidden,
            names
        );
    }
}

/// OCaml: module-qualified value paths (`Async.async`, `Io.read_file`)
/// expose the trailing value_name as an identifier. It should NOT be
/// classified as a local variable use — it's a module member reference.
#[test]
fn ocaml_module_qualified_paths_not_uninit() {
    let src = r#"let run_helper file =
  let contents = Io.read_file ~binary:false file in
  let result = Async.async (fun () -> contents) in
  Fpath.unlink_no_err (Path.to_string file);
  result
"#;
    let path = write_tmp("ocaml_modpath.ml", src);
    let (code, stdout, stderr) = run_tldr(&[
        "reaching-defs",
        path.to_str().unwrap(),
        "run_helper",
        "--format",
        "json",
    ]);
    assert_eq!(code, 0, "tldr reaching-defs failed: {} {}", stdout, stderr);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("not valid json");
    let names = uninit_vars(&v);
    for forbidden in &["read_file", "async", "unlink_no_err", "to_string"] {
        assert!(
            !names.iter().any(|n| n == forbidden),
            "OCaml: module-member '{}' should not be flagged as uninitialized. Got: {:?}",
            forbidden,
            names
        );
    }
}

// =============================================================================
// REAL-REPO DOGFOOD CASES (gated by corpus presence)
// =============================================================================

/// ts-dom-gen / emitWebIdl: pre-fix 731 FPs (every named import + every
/// method-call property name). Post-fix should be ZERO uninit entries
/// for that target — the function's params (webidl/global/iterator/
/// compilerBehavior) are already classified as definitions, every other
/// flagged identifier is an import or member-access property.
#[test]
fn typescript_emitwebidl_no_import_or_method_fps() {
    if !Path::new(TS_DOM_CORPUS).exists() {
        eprintln!("SKIP: corpus missing {}", TS_DOM_CORPUS);
        return;
    }
    let (code, stdout, _) = run_tldr(&[
        "reaching-defs",
        TS_DOM_CORPUS,
        "emitWebIdl",
        "--format",
        "json",
    ]);
    assert_eq!(code, 0, "tldr reaching-defs failed");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("not valid json");
    let names = uninit_vars(&v);
    // Specific imports / member-access properties from the audit:
    for forbidden in &[
        "createTextWriter",
        "getElements",
        "toNameMap",
        "mapToArray",
        "distinct",
        "mapValues",
        "mapDefined",
        "arrayToMap",
        "collectLegacyNamespaceTypes",
    ] {
        assert!(
            !names.iter().any(|n| n == forbidden),
            "TS dom-gen: '{}' must not be flagged. {} uninit entries: {:?}",
            forbidden,
            names.len(),
            &names.iter().take(10).collect::<Vec<_>>()
        );
    }
}

/// express/render: pre-fix 3 FPs (Array, Error, tryRender hoisted).
#[test]
fn javascript_render_globals_and_hoisted_funcs_not_flagged() {
    if !Path::new(JS_EXPRESS_CORPUS).exists() {
        eprintln!("SKIP: corpus missing {}", JS_EXPRESS_CORPUS);
        return;
    }
    let (code, stdout, _) = run_tldr(&[
        "reaching-defs",
        JS_EXPRESS_CORPUS,
        "render",
        "--format",
        "json",
    ]);
    assert_eq!(code, 0, "tldr reaching-defs failed");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("not valid json");
    let names = uninit_vars(&v);
    for forbidden in &["Array", "Error", "tryRender"] {
        assert!(
            !names.iter().any(|n| n == forbidden),
            "JS express: '{}' must not be flagged. Got: {:?}",
            forbidden,
            names
        );
    }
}

/// lua-lsp / m.open: pre-fix 3 FPs (`cache` field key, `m` module ref,
/// `onWatch` dot-index field name).
#[test]
fn lua_mopen_table_fields_and_module_refs_not_flagged() {
    if !Path::new(LUA_LSP_CORPUS).exists() {
        eprintln!("SKIP: corpus missing {}", LUA_LSP_CORPUS);
        return;
    }
    let (code, stdout, _) = run_tldr(&[
        "reaching-defs",
        LUA_LSP_CORPUS,
        "m.open",
        "--format",
        "json",
    ]);
    assert_eq!(code, 0, "tldr reaching-defs failed");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("not valid json");
    let names = uninit_vars(&v);
    for forbidden in &["cache", "m", "onWatch"] {
        assert!(
            !names.iter().any(|n| n == forbidden),
            "Lua: '{}' must not be flagged. Got: {:?}",
            forbidden,
            names
        );
    }
}

/// luau-luau / check (tables.luau): pre-fix 9 FPs including params
/// `t, na, nh` and globals `print`/`assert`.
#[test]
fn luau_check_params_and_globals_not_flagged() {
    if !Path::new(LUAU_CORPUS).exists() {
        eprintln!("SKIP: corpus missing {}", LUAU_CORPUS);
        return;
    }
    let (code, stdout, _) = run_tldr(&[
        "reaching-defs",
        LUAU_CORPUS,
        "check",
        "--format",
        "json",
    ]);
    assert_eq!(code, 0, "tldr reaching-defs failed");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("not valid json");
    let names = uninit_vars(&v);
    for forbidden in &["t", "na", "nh", "print", "assert"] {
        assert!(
            !names.iter().any(|n| n == forbidden),
            "Luau: '{}' must not be flagged. Got: {:?}",
            forbidden,
            names
        );
    }
}

/// csharp-newtonsoft-bson / ReadAsync: pre-fix 36 FPs including
/// enum-member access (`BsonReaderState.Normal`, .ReferenceStart etc.)
/// and method names on `this.X()` (`ReadNormalAsync`, `ReadReferenceAsync`).
#[test]
fn csharp_readasync_enum_and_methods_not_flagged() {
    if !Path::new(CSHARP_BSON_CORPUS).exists() {
        eprintln!("SKIP: corpus missing {}", CSHARP_BSON_CORPUS);
        return;
    }
    let (code, stdout, _) = run_tldr(&[
        "reaching-defs",
        CSHARP_BSON_CORPUS,
        "ReadAsync",
        "--format",
        "json",
    ]);
    assert_eq!(code, 0, "tldr reaching-defs failed");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("not valid json");
    let names = uninit_vars(&v);
    // In-scope for M-032: enum-member access NAMES (.Normal/.ReferenceStart/etc),
    // and bare same-file method-name callees (`ReadNormalAsync`, `ReadReferenceAsync`,
    // `ReadCodeWScopeAsync`, `ReadCatchingEndOfStreamAsync`). The receiver
    // type `BsonReaderState` lives in a SIBLING file (partial class) and
    // is therefore DESIGN-parked under cluster note "c11 reaching-defs
    // partial-class field resolution (DESIGN)" — we deliberately do NOT
    // assert that it disappears. We also don't assert about `_bsonReaderState`
    // (same partial-class field-resolution issue).
    for forbidden in &[
        "Normal",
        "ReferenceStart",
        "ReferenceRef",
        "ReferenceId",
        "ReadNormalAsync",
        "ReadReferenceAsync",
        "ReadCodeWScopeAsync",
        "ReadCatchingEndOfStreamAsync",
    ] {
        assert!(
            !names.iter().any(|n| n == forbidden),
            "C#: '{}' must not be flagged. Got: {:?}",
            forbidden,
            names
        );
    }
    // Strong invariant: pre-fix had 36 FPs. After in-scope fixes, the
    // count must drop substantially — locked at <=20 to guarantee the
    // in-scope FPs (method names + enum members on same-file partial)
    // are gone while leaving the partial-class DESIGN-parked items.
    assert!(
        names.len() <= 20,
        "C# ReadAsync: expected at most 20 uninit (down from 36), got {} ({:?})",
        names.len(),
        names
    );
}

/// ocaml-dune / run_expect_test: pre-fix many FPs (Module.value
/// references — `Io.read_file`, `Async.async`, `Fpath.unlink_no_err`,
/// `Path.to_string`, etc.).
#[test]
fn ocaml_run_expect_test_module_paths_not_flagged() {
    if !Path::new(OCAML_DUNE_CORPUS).exists() {
        eprintln!("SKIP: corpus missing {}", OCAML_DUNE_CORPUS);
        return;
    }
    let (code, stdout, _) = run_tldr(&[
        "reaching-defs",
        OCAML_DUNE_CORPUS,
        "run_expect_test",
        "--format",
        "json",
    ]);
    assert_eq!(code, 0, "tldr reaching-defs failed");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("not valid json");
    let names = uninit_vars(&v);
    for forbidden in &[
        "read_file",
        "async",
        "unlink_no_err",
        "to_string",
        "from_string",
        "extend_basename",
        "async_exn",
        "write_file",
    ] {
        assert!(
            !names.iter().any(|n| n == forbidden),
            "OCaml: module-member '{}' must not be flagged. Got: {:?}",
            forbidden,
            names
        );
    }
}
