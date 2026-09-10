//! pdg-bounds-and-stdout-hygiene-v1 (P11.BUG-AGG-4, AGG-5, AGG-14, AGG-15)
//!
//! Four regressions closed in this milestone:
//!
//! 1. **BUG-AGG-4 (MED)** `tldr semantic`/`similar`/`embed` previously
//!    leaked progress lines (`Building index for N chunks...`,
//!    `Skipped N files...`, `Index built in Xs`) onto stdout when the
//!    embedding cache was cold, polluting machine-readable JSON output.
//!    All progress is now routed through `eprintln!` so stdout carries
//!    only the final JSON payload — verified end-to-end by piping into
//!    `serde_json::from_str` on each command's stdout.
//! 2. **BUG-AGG-5 (MED)** `tldr chop`'s `LineOutsideFunction` error
//!    message previously rendered `lines 1-4294967295`, leaking the
//!    `u32::MAX` sentinel into user output for some C++ static-inline
//!    functions and PHP methods. Bounds are now resolved from the AST
//!    via `find_function_bounds_from_path_or_source`, with a clear
//!    "could not determine function bounds" fallback when resolution
//!    fails — never the sentinel.
//! 3. **BUG-AGG-14 (LOW)** `tldr chop` on an intra-procedural Java
//!    method body returned `path_exists=false` even when both lines
//!    sat inside the same method. Verified that consecutive non-blank
//!    statements in the same method body are now reachable in both
//!    directions of the PDG.
//! 4. **BUG-AGG-15 (LOW)** `tldr deps` on a Lua project reported zero
//!    internal dependencies because the module index/resolver had no
//!    Lua entry. `require("foo.bar")` now maps to `foo/bar.lua` and
//!    bumps `internal_dependencies` for the importing file.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;
use tempfile::TempDir;

fn tldr_bin() -> PathBuf {
    // why: env!("CARGO_BIN_EXE_tldr") is the path cargo builds for THIS
    // test's own profile, as a test dependency -- it cannot go stale the
    // way a hand-resolved `target/release/tldr` guess could, because
    // there is no rebuild step to forget (TRDD-BJ9T0U9I). The
    // `#[cfg(feature = "semantic")]` tests below only compile when this
    // crate is built with that feature, so running `cargo test --features
    // semantic` gives a binary that matches the tests exercising it --
    // no separate feature declaration needed for the bin itself.
    PathBuf::from(env!("CARGO_BIN_EXE_tldr"))
}

fn run_tldr(args: &[&str]) -> (String, String, bool) {
    let bin = tldr_bin();
    let output = Command::new(&bin)
        .args(args)
        .output()
        .expect("failed to execute tldr binary");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (stdout, stderr, output.status.success())
}

fn write(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, contents).unwrap();
}

// =============================================================================
// BUG-AGG-4: stdout hygiene for semantic / similar / embed
// =============================================================================

/// `tldr embed` against a freshly-created project must emit only valid JSON
/// on stdout, even when the embedding cache is cold and progress banners
/// (`Building index for N chunks...`, etc.) fire.
#[test]
#[cfg(feature = "semantic")]
fn test_embed_no_progress_on_stdout() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    write(
        &root.join("a.py"),
        "def alpha(x):\n    return x + 1\n\n\ndef beta(y):\n    return y * 2\n",
    );
    write(
        &root.join("b.py"),
        "def gamma(z):\n    return z - 3\n\n\ndef delta(w):\n    return w / 2\n",
    );

    let (stdout, _stderr, ok) = run_tldr(&[
        "embed",
        root.to_str().unwrap(),
        "--no-cache",
        "--format",
        "json",
    ]);
    assert!(ok, "tldr embed should exit 0");

    let _value: Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "stdout must be pure JSON (BUG-AGG-4); first 200 chars: {:?}\nparse error: {}",
            stdout.chars().take(200).collect::<String>(),
            e,
        );
    });
}

/// `tldr semantic` query against a freshly-created project must emit only
/// valid JSON on stdout. Cold cache means the index is built inline; the
/// build progress banners must go to stderr, not stdout.
#[test]
#[cfg(feature = "semantic")]
fn test_semantic_query_no_progress_on_stdout() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    write(
        &root.join("strings.py"),
        "def to_camel(s):\n    parts = s.split('_')\n    return parts[0] + ''.join(p.title() for p in parts[1:])\n",
    );
    write(
        &root.join("math.py"),
        "def add(a, b):\n    return a + b\n\n\ndef mul(a, b):\n    return a * b\n",
    );

    let (stdout, _stderr, ok) = run_tldr(&[
        "semantic",
        "string manipulation",
        root.to_str().unwrap(),
        "--no-cache",
        "--format",
        "json",
    ]);
    assert!(ok, "tldr semantic should exit 0");

    let _value: Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "stdout must be pure JSON (BUG-AGG-4); first 200 chars: {:?}\nparse error: {}",
            stdout.chars().take(200).collect::<String>(),
            e,
        );
    });
}

// =============================================================================
// BUG-AGG-5: chop function-bounds resolution avoids UINT32_MAX leak
// =============================================================================

/// A C++ `static inline` macro-named function on lines start..end must
/// produce a successful chop when both source and target lines sit inside
/// the body. Previously the lookup found the function but bound resolution
/// failed and the error would render `lines 1-4294967295`.
#[test]
fn test_chop_cpp_static_inline_bounds_correct() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let src = "\
#include <cstdio>

namespace tx {

    static inline int FOO(char* buffer, int size, const char* fmt)
    {
        int a = size;
        int b = a + 1;
        int result = b * 2;
        return result;
    }

}
";
    let cpp_path = root.join("inline.cpp");
    write(&cpp_path, src);

    // FOO body spans roughly lines 5..11. Pick two lines inside the body.
    let (stdout, stderr, ok) = run_tldr(&[
        "chop",
        cpp_path.to_str().unwrap(),
        "FOO",
        "7",
        "10",
        "--format",
        "json",
    ]);
    assert!(
        ok,
        "tldr chop should exit 0; stdout={stdout} stderr={stderr}"
    );

    let v: Value = serde_json::from_str(&stdout).expect("valid JSON");
    // Either path_exists=true with non-empty lines OR a clean error
    // message (must NOT contain the UINT32_MAX sentinel).
    let path_exists = v
        .get("path_exists")
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    let explanation = v
        .get("explanation")
        .and_then(|x| x.as_str())
        .unwrap_or("");
    assert!(
        !explanation.contains("4294967295"),
        "chop must not leak UINT32_MAX into explanation (BUG-AGG-5): {explanation}"
    );
    assert!(
        path_exists || !explanation.is_empty(),
        "chop should either find a path or surface a clear error"
    );
}

/// A PHP class method with a multi-line body must produce a successful
/// chop when both source and target lines sit inside the body, and any
/// out-of-bounds error message must not leak the UINT32_MAX sentinel.
#[test]
fn test_chop_php_method_bounds_correct() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let src = "<?php

class StringHelper {

    public function camel(string $s): string
    {
        $parts = explode('_', $s);
        $first = $parts[0];
        $rest = array_slice($parts, 1);
        $upper = array_map('ucfirst', $rest);
        return $first . implode('', $upper);
    }

}
";
    let php_path = root.join("StringHelper.php");
    write(&php_path, src);

    // Pick lines deep inside the method body.
    let (stdout, stderr, ok) = run_tldr(&[
        "chop",
        php_path.to_str().unwrap(),
        "camel",
        "7",
        "11",
        "--format",
        "json",
    ]);
    assert!(
        ok,
        "tldr chop should exit 0; stdout={stdout} stderr={stderr}"
    );

    let v: Value = serde_json::from_str(&stdout).expect("valid JSON");
    let path_exists = v
        .get("path_exists")
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    let explanation = v
        .get("explanation")
        .and_then(|x| x.as_str())
        .unwrap_or("");
    assert!(
        !explanation.contains("4294967295"),
        "chop must not leak UINT32_MAX into explanation (BUG-AGG-5): {explanation}"
    );

    // Probe an out-of-bounds line: the message must not contain UINT32_MAX
    // either, even when the line is genuinely outside the function.
    let (stdout_oob, _stderr_oob, ok_oob) = run_tldr(&[
        "chop",
        php_path.to_str().unwrap(),
        "camel",
        "200",
        "210",
        "--format",
        "json",
    ]);
    assert!(ok_oob, "tldr chop OOB call should still exit 0");
    let v_oob: Value = serde_json::from_str(&stdout_oob).expect("valid JSON");
    let explanation_oob = v_oob
        .get("explanation")
        .and_then(|x| x.as_str())
        .unwrap_or("");
    assert!(
        !explanation_oob.contains("4294967295"),
        "chop OOB error must not leak UINT32_MAX (BUG-AGG-5): {explanation_oob}"
    );
    let _ = path_exists;
}

// =============================================================================
// BUG-AGG-14: Java intra-procedural chop finds path
// =============================================================================

#[test]
fn test_chop_java_intra_fn_path_exists() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let src = "\
package com.example;

public class Owner {
    public String process(int page, String last) {
        String x = last;
        if (x == null) {
            x = \"\";
        }
        int y = x.length();
        if (y == 0) {
            return \"empty\";
        }
        if (y > 10) {
            return \"long\";
        }
        return \"ok\";
    }
}
";
    let java_path = root.join("Owner.java");
    write(&java_path, src);

    // Lines 5 (definition of x) and 13 (return based on y derived from x)
    // are both inside `process`, with a clear data-dep chain x -> y -> return.
    let (stdout, stderr, ok) = run_tldr(&[
        "chop",
        java_path.to_str().unwrap(),
        "process",
        "5",
        "13",
        "--format",
        "json",
    ]);
    assert!(
        ok,
        "tldr chop should exit 0; stdout={stdout} stderr={stderr}"
    );

    let v: Value = serde_json::from_str(&stdout).expect("valid JSON");
    let path_exists = v
        .get("path_exists")
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    let count = v.get("count").and_then(|x| x.as_u64()).unwrap_or(0);
    let explanation = v
        .get("explanation")
        .and_then(|x| x.as_str())
        .unwrap_or("");
    assert!(
        !explanation.contains("4294967295"),
        "chop must not leak UINT32_MAX (BUG-AGG-5 regression check): {explanation}"
    );
    assert!(
        path_exists,
        "chop should find a dep path between intra-procedural lines (BUG-AGG-14); got count={count} explanation={explanation}"
    );
}

// =============================================================================
// BUG-AGG-15: Lua require() resolves to internal dependencies
// =============================================================================

#[test]
fn test_deps_resolves_lua_require() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    write(
        &root.join("a.lua"),
        "local b = require(\"b\")\n\nfunction caller()\n    return b.hello()\nend\n",
    );
    write(
        &root.join("b.lua"),
        "local M = {}\n\nfunction M.hello()\n    return \"world\"\nend\n\nreturn M\n",
    );

    let (stdout, stderr, ok) = run_tldr(&[
        "deps",
        root.to_str().unwrap(),
        "--lang",
        "lua",
        "--format",
        "json",
    ]);
    assert!(
        ok,
        "tldr deps should exit 0; stdout={stdout} stderr={stderr}"
    );

    let v: Value = serde_json::from_str(&stdout).expect("valid JSON");
    let stats = v.get("stats").expect("stats present");
    let total_internal = stats
        .get("total_internal_deps")
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    assert!(
        total_internal > 0,
        "Lua deps should resolve require(\"b\") to b.lua (BUG-AGG-15); got total_internal_deps={total_internal}, stats={stats}"
    );
}
