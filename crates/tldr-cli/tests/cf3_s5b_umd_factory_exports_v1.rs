//! CF3-S5b generalization + false-positive guard: UMD/IIFE factory-return
//! module exports (lodash `lodash.js` idiom).
//!
//! The whole library is wrapped in `;(function(){ … }.call(this))`; its public
//! surface is decorated onto the object an inner factory `return`s, then bound
//! to CommonJS via `<moduleRef>.exports = <id>`. Before the fix, neither
//! `tldr interface` nor `tldr surface` descended into the IIFE, so both reported
//! ZERO exports for lodash.
//!
//! These tests assert BOTH halves of the slice contract:
//!   (a) a faithful UMD factory-return fixture (and the real lodash corpus when
//!       present) yields NON-ZERO exports including the real members
//!       `map`/`filter`/`reduce`, for BOTH `interface` and `surface`; and
//!   (b) the false-positive guard holds — a non-module `foo.exports = bar`
//!       (where `foo` is not a provable module reference) mints ZERO exports,
//!       and a plain non-UMD CommonJS module keeps its existing export surface.
//!
//! The resolver is purely AST-driven: the module-export sink is gated on
//! binding provenance (the alias's initializer structurally tests
//! `typeof module`/`typeof exports`), never on a hardcoded name list.

use assert_cmd::Command;
use serde_json::Value;
use std::path::Path;
use tempfile::TempDir;

/// A faithful reproduction of the lodash `lodash.js` UMD/IIFE factory-return
/// export idiom. The whole module is an IIFE; `freeModule` is bound from a
/// `typeof module`/`typeof exports` detection chain; the public API is
/// decorated onto the object returned by the inner `runInContext` factory and
/// exported via `(freeModule.exports = _)._ = _`.
const UMD_LODASH_FIXTURE: &str = r#"
;(function() {
  var freeExports = typeof exports == 'object' && exports && !exports.nodeType && exports;
  var freeModule = freeExports && typeof module == 'object' && module && !module.nodeType && module;

  var runInContext = (function runInContext(context) {
    function lodash(value) { return value; }
    function map(collection, iteratee) { return collection; }
    function filter(collection, predicate) { return collection; }
    function reduce(collection, iteratee, accumulator) { return accumulator; }
    function chunk(array, size) { return array; }
    lodash.chunk = chunk;
    lodash.map = map;
    lodash.filter = filter;
    lodash.reduce = reduce;
    lodash.VERSION = '4.17.21';
    return lodash;
  });

  var _ = runInContext();

  if (typeof define == 'function' && typeof define.amd == 'object' && define.amd) {
    root._ = _;
    define(function() { return _; });
  }
  else if (freeModule) {
    (freeModule.exports = _)._ = _;
    freeExports._ = _;
  }
  else {
    root._ = _;
  }
}.call(this));
"#;

/// False-positive guard: the SAME structural shape (IIFE, factory-decorated
/// object, `<x>.exports = <id>` sink) but `foo` is NOT a module reference — it
/// is bound from an unrelated call, with no `typeof module`/`typeof exports`
/// provenance. The resolver must mint ZERO exports here.
const NON_MODULE_FIXTURE: &str = r#"
;(function() {
  var foo = makeContainer();
  var bar = (function() {
    function widget(v) { return v; }
    widget.map = function(c) { return c; };
    widget.filter = function(c) { return c; };
    return widget;
  })();
  foo.exports = bar;
}.call(this));
"#;

/// False-positive guard: a plain, non-UMD CommonJS module. The existing
/// top-level export engine already handles this; the new IIFE resolver must not
/// disturb it (no IIFE present), so `createApplication` and `json` still surface.
const PLAIN_CJS_FIXTURE: &str = r#"
function createApplication() { return {}; }
function jsonParser() { return null; }
module.exports = createApplication;
createApplication.json = jsonParser;
"#;

fn write_fixture(dir: &Path, name: &str, contents: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, contents).expect("write fixture");
    path
}

fn run_json(subcommand: &str, file: &Path) -> Value {
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .env("TLDR_NO_DAEMON", "1")
        .args([subcommand, file.to_str().unwrap(), "--format", "json"])
        .output()
        .expect("run tldr");
    assert!(
        output.status.success(),
        "`tldr {subcommand}` failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "non-JSON output from `tldr {subcommand}`: {e}\n{}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

/// The set of exported member names from `tldr interface` JSON.
fn interface_export_names(v: &Value) -> Vec<String> {
    v["all_exports"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

/// The set of exported member (leaf) names from `tldr surface` JSON.
fn surface_export_names(v: &Value) -> Vec<String> {
    v["apis"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x["qualified_name"].as_str())
                .map(|q| q.rsplit('.').next().unwrap_or(q).to_string())
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn umd_factory_return_exports_resolved_for_interface() {
    let dir = TempDir::new().unwrap();
    let file = write_fixture(dir.path(), "umd_lodash.js", UMD_LODASH_FIXTURE);

    let v = run_json("interface", &file);
    let names = interface_export_names(&v);

    // (a) NON-ZERO and includes the real factory-decorated members.
    assert!(
        !names.is_empty(),
        "interface should resolve UMD factory-return exports, got none: {names:?}"
    );
    for expected in ["map", "filter", "reduce", "chunk"] {
        assert!(
            names.iter().any(|n| n == expected),
            "interface UMD exports missing `{expected}`: {names:?}"
        );
    }
    // The non-function decorated member surfaces too (as a value export).
    assert!(
        names.iter().any(|n| n == "VERSION"),
        "interface UMD exports missing value member `VERSION`: {names:?}"
    );

    // map/filter/reduce/chunk are resolved to real functions with signatures.
    let funcs = v["functions"].as_array().cloned().unwrap_or_default();
    assert!(
        funcs.iter().any(|f| f["name"] == "map"),
        "`map` should be a resolved function, not a bare value"
    );
}

#[test]
fn umd_factory_return_exports_resolved_for_surface() {
    let dir = TempDir::new().unwrap();
    let file = write_fixture(dir.path(), "umd_lodash.js", UMD_LODASH_FIXTURE);

    let v = run_json("surface", &file);
    let names = surface_export_names(&v);

    assert!(
        v["total"].as_u64().unwrap_or(0) > 0,
        "surface should resolve UMD factory-return exports, got total 0"
    );
    for expected in ["map", "filter", "reduce", "chunk"] {
        assert!(
            names.iter().any(|n| n == expected),
            "surface UMD exports missing `{expected}`: {names:?}"
        );
    }
}

#[test]
fn non_module_exports_sink_mints_zero_false_positives() {
    let dir = TempDir::new().unwrap();
    let file = write_fixture(dir.path(), "not_a_module.js", NON_MODULE_FIXTURE);

    // `foo` is NOT a provable module reference, so `foo.exports = bar` is not a
    // module-export sink. BOTH commands must mint ZERO exports.
    let iface = run_json("interface", &file);
    let iface_names = interface_export_names(&iface);
    assert!(
        iface_names.is_empty(),
        "non-module foo.exports=bar must yield no interface exports, got {iface_names:?}"
    );
    // Specifically none of the decoy members leaked through.
    for leaked in ["map", "filter"] {
        assert!(
            !iface_names.iter().any(|n| n == leaked),
            "false positive: `{leaked}` leaked from a non-module sink"
        );
    }

    let surf = run_json("surface", &file);
    assert_eq!(
        surf["total"].as_u64().unwrap_or(u64::MAX),
        0,
        "non-module foo.exports=bar must yield no surface exports"
    );
}

#[test]
fn plain_commonjs_module_surface_unchanged() {
    let dir = TempDir::new().unwrap();
    let file = write_fixture(dir.path(), "plain_cjs.js", PLAIN_CJS_FIXTURE);

    // No IIFE: the new resolver is inert and the existing top-level CommonJS
    // engine still surfaces the real exports.
    let v = run_json("interface", &file);
    let names = interface_export_names(&v);
    assert!(
        names.iter().any(|n| n == "createApplication"),
        "plain CJS export `createApplication` must remain visible: {names:?}"
    );
    assert!(
        names.iter().any(|n| n == "json"),
        "plain CJS member export `json` must remain visible: {names:?}"
    );
}

/// Bonus coverage against the real lodash corpus when it is present on this
/// machine. Skips cleanly when the corpus is absent so the suite stays portable.
#[test]
fn real_lodash_corpus_exports_nonzero_when_present() {
    let corpus = Path::new("/Users/cosimo/.tldr-audit/corpora/js-lodash/lodash.js");
    if !corpus.is_file() {
        eprintln!("skipping: lodash corpus not present at {}", corpus.display());
        return;
    }

    let iface = run_json("interface", corpus);
    let iface_names = interface_export_names(&iface);
    assert!(
        iface_names.len() > 100,
        "real lodash interface should expose its large API surface, got {}",
        iface_names.len()
    );
    for expected in ["map", "filter", "reduce"] {
        assert!(
            iface_names.iter().any(|n| n == expected),
            "real lodash interface missing `{expected}`"
        );
    }

    let surf = run_json("surface", corpus);
    let surf_names = surface_export_names(&surf);
    assert!(
        surf["total"].as_u64().unwrap_or(0) > 100,
        "real lodash surface should expose its large API surface"
    );
    for expected in ["map", "filter", "reduce"] {
        assert!(
            surf_names.iter().any(|n| n == expected),
            "real lodash surface missing `{expected}`"
        );
    }
}
