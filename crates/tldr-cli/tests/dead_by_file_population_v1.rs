//! dead-by-file-population-v1 — CLUSTER-M-045 (v0.4.2).
//!
//! Pre-fix: `tldr dead` emits `by_file: {}` even when `possibly_dead` is
//! non-empty. The emitter populates `by_file` only from `dead_functions`
//! (private/unenriched uncalled) and forgets to bucket `possibly_dead`
//! (public/exported uncalled) entries by file. Downstream consumers cannot
//! compute "which file has the most possibly-dead funcs" without re-grouping
//! the array themselves.
//!
//! Post-fix:
//! - `by_file` is non-empty whenever `dead_functions` OR `possibly_dead`
//!   is non-empty.
//! - For each entry in `dead_functions + possibly_dead`, there is exactly
//!   one corresponding bucket entry under `by_file[entry.file]` carrying
//!   `entry.name` (after Elixir qualified/unqualified dedup).
//! - Elixir-specific: when the same file emits both `Module.foo` (qualified)
//!   and `foo` (bare unqualified), the unqualified bare name is dropped at
//!   collection time. The Elixir AST extractor surfaces every `def` as
//!   BOTH a top-level function AND a method of the enclosing-module
//!   "class"; without dedup the same function appears twice in
//!   `possibly_dead`.
//!
//! Affected langs (audited): scala, lua, c, javascript, elixir (5 langs).
//!
//! AST/data-only fix: aggregation happens in the dead-code emitter
//! (`crates/tldr-core/src/analysis/dead.rs`) over `FunctionRef.file` paths
//! produced by `collect_all_functions`. No string parsing of file paths
//! beyond `PathBuf` canonicalization.

use assert_cmd::Command;
use serde_json::Value;
use std::collections::HashSet;
use std::fs;
use tempfile::TempDir;

fn run_tldr(args: &[&str]) -> (i32, String, String) {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("tldr"));
    let output = cmd.args(args).output().expect("tldr binary missing");
    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (code, stdout, stderr)
}

/// Helper: collect all names from a value array's `name` field.
fn names(arr: &[Value]) -> Vec<String> {
    arr.iter()
        .filter_map(|v| v.get("name").and_then(|n| n.as_str()).map(String::from))
        .collect()
}

/// Helper: assert by_file map invariants on a dead-code JSON report:
///   1. by_file is non-empty when (dead_functions + possibly_dead) is non-empty.
///   2. Every name in (dead_functions + possibly_dead) appears under exactly
///      one by_file bucket (set-equality on bag of names).
fn assert_by_file_population(v: &Value, lang_label: &str) {
    let dead_functions = v
        .get("dead_functions")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    let possibly_dead = v
        .get("possibly_dead")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    let by_file = v
        .get("by_file")
        .and_then(|x| x.as_object())
        .cloned()
        .expect("by_file must be a JSON object");

    let all_names: HashSet<String> = names(&dead_functions)
        .into_iter()
        .chain(names(&possibly_dead).into_iter())
        .collect();

    assert!(
        !all_names.is_empty(),
        "[{}] fixture sanity check: expected at least one entry in \
         dead_functions+possibly_dead; got none. JSON:\n{}",
        lang_label,
        serde_json::to_string_pretty(v).unwrap_or_default()
    );

    assert!(
        !by_file.is_empty(),
        "[{}] by_file must be non-empty when dead_functions+possibly_dead has \
         {} entries. JSON:\n{}",
        lang_label,
        all_names.len(),
        serde_json::to_string_pretty(v).unwrap_or_default()
    );

    // Collect every name across every by_file bucket.
    let mut by_file_names: HashSet<String> = HashSet::new();
    for (_path, funcs) in by_file.iter() {
        let arr = funcs
            .as_array()
            .unwrap_or_else(|| panic!("[{}] by_file value must be an array", lang_label));
        for n in arr {
            if let Some(s) = n.as_str() {
                by_file_names.insert(s.to_string());
            }
        }
    }

    assert_eq!(
        by_file_names, all_names,
        "[{}] by_file bag-of-names must equal dead_functions+possibly_dead \
         bag-of-names.\nby_file: {:?}\nall_names: {:?}",
        lang_label, by_file_names, all_names
    );
}

// =============================================================================
// M-045: by_file populated for all 5 audited languages
// =============================================================================

/// Scala: a class with two public uncalled methods must produce a non-empty
/// `by_file` map containing both method names.
#[test]
fn test_scala_dead_by_file_populated() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("Foo.scala"),
        r#"package example

class Foo {
  def helperPublicUncalled(x: Int): Int = x * 2
  def anotherPublicUncalled(s: String): String = s + "!"
}

object Main {
  def main(args: Array[String]): Unit = {
    println("hi")
  }
}
"#,
    )
    .unwrap();

    let path = dir.path().to_string_lossy().to_string();
    let (code, stdout, stderr) =
        run_tldr(&["dead", &path, "--lang", "scala", "--format", "json", "-q"]);
    assert_eq!(code, 0, "tldr dead (scala) failed: {}", stderr);

    let v: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("scala dead output not JSON: {}\n{}", e, stdout));

    assert_by_file_population(&v, "scala");
}

/// Lua: a module table with public uncalled methods (`M.foo`) must populate
/// `by_file`.
#[test]
fn test_lua_dead_by_file_populated() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("lib.lua"),
        r#"local M = {}

function M.deadOne()
    return 1
end

function M.deadTwo()
    return 2
end

function M.entry()
    print("hi")
end

return M
"#,
    )
    .unwrap();

    let path = dir.path().to_string_lossy().to_string();
    let (code, stdout, stderr) =
        run_tldr(&["dead", &path, "--lang", "lua", "--format", "json", "-q"]);
    assert_eq!(code, 0, "tldr dead (lua) failed: {}", stderr);

    let v: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("lua dead output not JSON: {}\n{}", e, stdout));

    assert_by_file_population(&v, "lua");
}

/// C: top-level uncalled functions must populate `by_file`.
#[test]
fn test_c_dead_by_file_populated() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("lib.c"),
        r#"#include <stdio.h>

int dead_helper(int x) {
    return x * 2;
}

int another_dead(int y) {
    return y + 1;
}

int main(void) {
    return 0;
}
"#,
    )
    .unwrap();

    let path = dir.path().to_string_lossy().to_string();
    let (code, stdout, stderr) =
        run_tldr(&["dead", &path, "--lang", "c", "--format", "json", "-q"]);
    assert_eq!(code, 0, "tldr dead (c) failed: {}", stderr);

    let v: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("c dead output not JSON: {}\n{}", e, stdout));

    assert_by_file_population(&v, "c");
}

/// JavaScript: exported uncalled functions must populate `by_file`.
#[test]
fn test_javascript_dead_by_file_populated() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("lib.js"),
        r#"export function deadOne() { return 1; }
export function deadTwo() { return 2; }

export function main() { console.log("hi"); }
"#,
    )
    .unwrap();

    let path = dir.path().to_string_lossy().to_string();
    let (code, stdout, stderr) = run_tldr(&[
        "dead",
        &path,
        "--lang",
        "javascript",
        "--format",
        "json",
        "-q",
    ]);
    assert_eq!(code, 0, "tldr dead (javascript) failed: {}", stderr);

    let v: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("javascript dead output not JSON: {}\n{}", e, stdout));

    assert_by_file_population(&v, "javascript");
}

/// Elixir: by_file is populated AND there are no qualified/unqualified
/// dupes within the same file's bucket. Pre-fix the Elixir AST extractor
/// emits each `def` as BOTH a top-level function `foo` AND a method
/// `Module.foo` under the enclosing-module pseudo-class, so the same
/// function appears twice in `possibly_dead`. Post-fix the qualified form
/// shadows the bare form.
#[test]
fn test_elixir_dead_by_file_populated_and_deduped() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("helpers.ex"),
        r#"defmodule MyApp.Helpers do
  def dead_one(x), do: x + 1
  def dead_two(y), do: y * 2
  def main do
    IO.puts("hi")
  end
end
"#,
    )
    .unwrap();

    let path = dir.path().to_string_lossy().to_string();
    let (code, stdout, stderr) = run_tldr(&[
        "dead",
        &path,
        "--lang",
        "elixir",
        "--format",
        "json",
        "-q",
    ]);
    assert_eq!(code, 0, "tldr dead (elixir) failed: {}", stderr);

    let v: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("elixir dead output not JSON: {}\n{}", e, stdout));

    // (a) by_file populated
    assert_by_file_population(&v, "elixir");

    // (b) no qualified/unqualified pair within the same bucket
    let by_file = v
        .get("by_file")
        .and_then(|x| x.as_object())
        .expect("elixir: by_file must be an object");

    for (path_key, funcs) in by_file.iter() {
        let names_arr: Vec<String> = funcs
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
        let bare_names: HashSet<&str> = names_arr
            .iter()
            .map(|n| n.rsplit('.').next().unwrap_or(n.as_str()))
            .collect();
        let qualified_bares: HashSet<&str> = names_arr
            .iter()
            .filter(|n| n.contains('.'))
            .map(|n| n.rsplit('.').next().unwrap_or(n.as_str()))
            .collect();
        // For every qualified name's bare suffix, the bare-only form must NOT
        // also appear under the same bucket.
        for q in &qualified_bares {
            let has_bare_only = names_arr.iter().any(|n| !n.contains('.') && n == q);
            assert!(
                !has_bare_only,
                "elixir: file {} contains both qualified `*.{}` and bare `{}` \
                 entries — qualified/unqualified dedup failed.\nNames: {:?}",
                path_key, q, q, names_arr
            );
        }
        let _ = bare_names;
    }

    // (c) Also assert top-level `possibly_dead` array has no qualified/
    // unqualified duplicate pairs (same file + same suffix).
    let possibly_dead = v
        .get("possibly_dead")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    let mut per_file: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    for entry in &possibly_dead {
        let file = entry
            .get("file")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let name = entry
            .get("name")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        per_file.entry(file).or_default().push(name);
    }
    for (file, names_in_file) in &per_file {
        for n in names_in_file {
            if n.contains('.') {
                let bare = n.rsplit('.').next().unwrap_or(n);
                let bare_alone_present =
                    names_in_file.iter().any(|m| m == bare && bare != n);
                assert!(
                    !bare_alone_present,
                    "elixir possibly_dead: file {} has both `{}` and bare `{}` \
                     — qualified/unqualified dedup failed.\nentries: {:?}",
                    file, n, bare, names_in_file
                );
            }
        }
    }
}

// =============================================================================
// M-044 non-regression: cpp destructors/virtual still excluded
// =============================================================================

/// Regression guard: M-044 fix must remain in effect. A C++ destructor
/// (`~Widget`) must never appear in dead_functions, possibly_dead, or
/// by_file post the M-045 emitter change.
#[test]
fn test_m044_nonregression_cpp_destructor_still_excluded() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("widget.cpp"),
        r#"
class Widget {
public:
    Widget() {}
    ~Widget() {}
    void doWork() {}
};

int main() {
    return 0;
}
"#,
    )
    .unwrap();

    let path = dir.path().to_string_lossy().to_string();
    let (code, stdout, stderr) =
        run_tldr(&["dead", &path, "--lang", "cpp", "--format", "json", "-q"]);
    assert_eq!(code, 0, "tldr dead (cpp) failed: {}", stderr);

    let v: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("cpp dead output not JSON: {}\n{}", e, stdout));

    // No ~Widget anywhere
    for key in &["dead_functions", "possibly_dead"] {
        if let Some(arr) = v.get(*key).and_then(|x| x.as_array()) {
            for item in arr {
                let name = item.get("name").and_then(|n| n.as_str()).unwrap_or("");
                let bare = name.rsplit('.').next().unwrap_or(name);
                assert!(
                    !bare.starts_with('~'),
                    "C++ destructor '{}' must not appear in '{}' (M-044 regression)",
                    name,
                    key
                );
            }
        }
    }
    if let Some(by_file) = v.get("by_file").and_then(|x| x.as_object()) {
        for (_p, funcs) in by_file.iter() {
            if let Some(arr) = funcs.as_array() {
                for n in arr {
                    let s = n.as_str().unwrap_or("");
                    let bare = s.rsplit('.').next().unwrap_or(s);
                    assert!(
                        !bare.starts_with('~'),
                        "C++ destructor '{}' must not appear in by_file (M-044 regression)",
                        s
                    );
                }
            }
        }
    }
}
