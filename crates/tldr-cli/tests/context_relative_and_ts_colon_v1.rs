//! context-relative-and-ts-colon-v1 (P15.AGG15-2): regression where
//! `tldr context "<file>:<func>"` collapsed the BFS callee traversal
//! to a single function (the entry point) when the call graph stored
//! its keys with a different shape than the file_filter early-return
//! produced. Two specific symptoms motivated the fix:
//!
//!   - **csharp** (BUG-2 in P15 audit): the call graph stores
//!     `BsonBinaryWriter.WriteToken` (class-prefixed) with a
//!     project-relative file path, but
//!     `find_function_in_graph`'s direct-extract early-return produced
//!     `(rel, "WriteToken")` (bare name). BFS lookup on
//!     `(rel, "WriteToken")` found zero outgoing edges, dropping the
//!     result from 9 functions to 1.
//!   - **js** (express): same shape but caused by file-path divergence
//!     between the call graph's stored relative path and the
//!     direct-extract path. BFS lookup missed all outgoing edges,
//!     dropping 6 → 1.
//!
//! The fix adds `find_call_graph_key`, which is consulted in the
//! `file_filter` early-return path of `find_function_in_graph`. When
//! the call graph contains an edge whose file canonicalises to
//! `file_filter` and whose function is `func_name` or
//! `<Class>.{func_name}`, we return the graph's own key so BFS finds
//! the outgoing edges. Falls back to the direct-extract key when no
//! graph edge matches (preserving correct behaviour for leaf
//! functions and single-file projects).
//!
//! Per `no-synthetic-fixtures-v1`: each test gates on real-repo
//! presence (`/tmp/repos/<repo>`), uses `≥ N`-style numeric thresholds
//! the canonical real-repo material guarantees, and exercises the
//! exact `<file>:<func>` invocation surface that regressed.

use std::path::Path;
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

/// Run tldr with explicit working directory so we can pass relative
/// file paths from inside the target repo (the exact invocation
/// pattern AGG15-2 regressed for).
fn run_tldr_in(cwd: &str, args: &[&str]) -> (i32, String) {
    let out = Command::new(tldr_bin())
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("failed to run tldr binary");
    let exit = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    (exit, stdout)
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

fn func_count(v: &serde_json::Value) -> usize {
    v["functions"].as_array().map(|a| a.len()).unwrap_or(0)
}

fn entry_point<'a>(v: &'a serde_json::Value) -> &'a str {
    v["entry_point"].as_str().unwrap_or("")
}

// ============================================================================
// Bug 3 (primary AGG15-2): callee traversal recovered for csharp + js
// ============================================================================

/// **csharp ABS form** — `tldr context "/abs/path/file.cs:WriteToken"` must
/// return ≥ 5 functions (callees expanded). P15 returned 1 because the call
/// graph key was `BsonBinaryWriter.WriteToken` while find_function_in_graph
/// returned `WriteToken`.
#[test]
fn csharp_context_file_func_absolute_returns_callees() {
    let file = "/tmp/repos/csharp-newtonsoft-bson-full/Src/Newtonsoft.Json.Bson/BsonBinaryWriter.cs";
    if !Path::new(file).exists() {
        return;
    }
    let arg = format!("{}:WriteToken", file);
    let (rc, out) = run_tldr(&["context", &arg, "--format", "json"]);
    assert_eq!(rc, 0, "tldr context rc != 0; stdout={}", out);
    let v = parse_json(&out);
    assert_eq!(entry_point(&v), "WriteToken");
    let n = func_count(&v);
    assert!(
        n >= 5,
        "csharp context absolute file:fn returned {} functions; expected ≥ 5 \
         (P15 regression collapsed to 1 because BFS could not match graph key \
         `BsonBinaryWriter.WriteToken` against direct-extract key `WriteToken`)",
        n
    );
}

/// **csharp REL form** — same probe but with cwd inside the repo and a
/// project-relative path. Both forms must produce identical results.
#[test]
fn csharp_context_file_func_relative_returns_callees() {
    let repo = "/tmp/repos/csharp-newtonsoft-bson-full";
    if !Path::new(repo).exists() {
        return;
    }
    let (rc, out) = run_tldr_in(
        repo,
        &[
            "context",
            "Src/Newtonsoft.Json.Bson/BsonBinaryWriter.cs:WriteToken",
            "--format",
            "json",
        ],
    );
    assert_eq!(rc, 0, "tldr context rc != 0; stdout={}", out);
    let v = parse_json(&out);
    assert_eq!(entry_point(&v), "WriteToken");
    let n = func_count(&v);
    assert!(
        n >= 5,
        "csharp context relative file:fn returned {} functions; expected ≥ 5",
        n
    );
}

/// **js ABS form** — `tldr context "/abs/path/lib/application.js:render"`
/// must return ≥ 5 functions. P15 collapsed to 1.
#[test]
fn js_context_file_func_absolute_returns_callees() {
    let file = "/tmp/repos/express/lib/application.js";
    if !Path::new(file).exists() {
        return;
    }
    let arg = format!("{}:render", file);
    let (rc, out) = run_tldr(&["context", &arg, "--format", "json"]);
    assert_eq!(rc, 0, "tldr context rc != 0; stdout={}", out);
    let v = parse_json(&out);
    assert_eq!(entry_point(&v), "render");
    let n = func_count(&v);
    assert!(
        n >= 5,
        "js context absolute file:fn returned {} functions; expected ≥ 5 \
         (was 6 in P14, collapsed to 1 in P15)",
        n
    );
}

/// **js REL form** — same probe with cwd inside the repo.
#[test]
fn js_context_file_func_relative_returns_callees() {
    let repo = "/tmp/repos/express";
    if !Path::new(repo).exists() {
        return;
    }
    let (rc, out) = run_tldr_in(
        repo,
        &["context", "lib/application.js:render", "--format", "json"],
    );
    assert_eq!(rc, 0, "tldr context rc != 0; stdout={}", out);
    let v = parse_json(&out);
    assert_eq!(entry_point(&v), "render");
    let n = func_count(&v);
    assert!(
        n >= 5,
        "js context relative file:fn returned {} functions; expected ≥ 5",
        n
    );
}

// ============================================================================
// Bug 2 (AGG14-8 verification): typescript file:fn must NOT mangle name
// ============================================================================

/// The pre-P14-A symptom was that `tldr context emitter.ts:emitWebIdl`
/// would parse the name as `tsmitWebIdl` (the parser split on the wrong
/// colon position when the file extension contained `.ts:`). P14-A's
/// "smart colon parser" walks colons right-to-left and picks the
/// leftmost split whose file_part is a real file. This test pins that
/// behaviour to prevent re-regression.
#[test]
fn typescript_context_file_func_does_not_mangle_name() {
    let file = "/tmp/repos/ts-dom-gen/src/build/emitter.ts";
    if !Path::new(file).exists() {
        return;
    }
    let arg = format!("{}:emitWebIdl", file);
    let (rc, out) = run_tldr(&["context", &arg, "--format", "json"]);
    assert_eq!(rc, 0, "tldr context rc != 0; stdout={}", out);
    let v = parse_json(&out);
    let entry = entry_point(&v);
    assert_eq!(
        entry, "emitWebIdl",
        "typescript context file:fn mangled the function name: got `{}`, \
         expected `emitWebIdl`. AGG14-8 regression — the colon-form parser \
         split on the wrong position when the input contained `.ts:`",
        entry
    );
    assert_ne!(
        entry, "tsmitWebIdl",
        "typescript context file:fn produced the legacy mangled name `tsmitWebIdl`",
    );
    let n = func_count(&v);
    assert!(
        n >= 1,
        "typescript context file:fn returned {} functions; expected ≥ 1",
        n
    );
}

/// **typescript REL form** — same probe via cwd-relative path.
#[test]
fn typescript_context_file_func_relative_does_not_mangle_name() {
    let repo = "/tmp/repos/ts-dom-gen";
    if !Path::new(repo).exists() {
        return;
    }
    let (rc, out) = run_tldr_in(
        repo,
        &[
            "context",
            "src/build/emitter.ts:emitWebIdl",
            "--format",
            "json",
        ],
    );
    assert_eq!(rc, 0, "tldr context rc != 0; stdout={}", out);
    let v = parse_json(&out);
    assert_eq!(entry_point(&v), "emitWebIdl");
}

// ============================================================================
// Bug 1 (AGG13-5 relative-path 8 langs): relative-path file:fn resolves
// across the major language adapters that P14-A's relative-form fix had
// to cover. These guard against AGG13-5 oscillation.
// ============================================================================

/// **php** — relative-path file:fn from inside symfony-string repo.
#[test]
fn php_context_relative_file_func_slice() {
    let repo = "/tmp/repos/php-symfony-string";
    if !Path::new(repo).exists() {
        return;
    }
    let (rc, out) = run_tldr_in(
        repo,
        &["context", "AbstractString.php:slice", "--format", "json"],
    );
    assert_eq!(rc, 0, "php context rc != 0; stdout={}", out);
    let v = parse_json(&out);
    assert_eq!(entry_point(&v), "slice");
    assert!(func_count(&v) >= 1);
}

/// **scala** — deeply-nested relative path.
#[test]
fn scala_context_relative_file_func_flatmap() {
    let repo = "/tmp/repos/scala-cats-effect";
    let file = "/tmp/repos/scala-cats-effect/core/shared/src/main/scala/cats/effect/IO.scala";
    if !Path::new(file).exists() {
        return;
    }
    let (rc, out) = run_tldr_in(
        repo,
        &[
            "context",
            "core/shared/src/main/scala/cats/effect/IO.scala:flatMap",
            "--format",
            "json",
        ],
    );
    assert_eq!(rc, 0, "scala context rc != 0; stdout={}", out);
    let v = parse_json(&out);
    assert_eq!(entry_point(&v), "flatMap");
    assert!(func_count(&v) >= 1);
}

/// **rust** — relative-path file:fn from inside ripgrep.
#[test]
fn rust_context_relative_file_func_glob_new() {
    let repo = "/tmp/repos/ripgrep";
    if !Path::new(repo).exists() {
        return;
    }
    let (rc, out) = run_tldr_in(
        repo,
        &[
            "context",
            "crates/globset/src/glob.rs:new",
            "--format",
            "json",
        ],
    );
    assert_eq!(rc, 0, "rust context rc != 0; stdout={}", out);
    let v = parse_json(&out);
    assert_eq!(entry_point(&v), "new");
    assert!(func_count(&v) >= 1);
}

/// **kotlin** — relative-path with the file that actually exists in the
/// kotlin-datetime repo (`DeprecatedInstant.kt`, not `Instant.kt` —
/// auditor used a stale filename).
#[test]
fn kotlin_context_relative_file_func_plus() {
    let repo = "/tmp/repos/kotlin-datetime";
    let file = "/tmp/repos/kotlin-datetime/core/common/src/DeprecatedInstant.kt";
    if !Path::new(file).exists() {
        return;
    }
    let (rc, out) = run_tldr_in(
        repo,
        &[
            "context",
            "core/common/src/DeprecatedInstant.kt:plus",
            "--format",
            "json",
        ],
    );
    assert_eq!(rc, 0, "kotlin context rc != 0; stdout={}", out);
    let v = parse_json(&out);
    assert_eq!(entry_point(&v), "plus");
    assert!(func_count(&v) >= 1);
}

/// **lua** — `m.reset` (table-method form) via relative path.
#[test]
fn lua_context_relative_file_func_m_reset() {
    let repo = "/tmp/repos/lua-lsp";
    // CORPUS_ENV: the present lua-lsp checkout does not contain
    // `script/files.lua` (this fixture pins a different lua corpus layout
    // with the table-method `m.reset` form). Guard on the actual target
    // file, not just the repo dir, so we skip cleanly when unavailable.
    if !Path::new(repo).join("script/files.lua").exists() {
        eprintln!("[skip] {}/script/files.lua not present", repo);
        return;
    }
    let (rc, out) = run_tldr_in(
        repo,
        &[
            "context",
            "script/files.lua:m.reset",
            "--format",
            "json",
        ],
    );
    assert_eq!(rc, 0, "lua context rc != 0; stdout={}", out);
    let v = parse_json(&out);
    assert_eq!(entry_point(&v), "m.reset");
    assert!(func_count(&v) >= 1);
}

/// **elixir** — relative-path file:fn from inside plug.
#[test]
fn elixir_context_relative_file_func_assign() {
    let repo = "/tmp/repos/elixir-plug";
    // CORPUS_ENV: the present elixir-plug checkout has empty source dirs
    // (no `.ex` files), so `lib/plug/conn.ex` is absent. Guard on the
    // actual target file rather than the repo dir.
    if !Path::new(repo).join("lib/plug/conn.ex").exists() {
        eprintln!("[skip] {}/lib/plug/conn.ex not present", repo);
        return;
    }
    let (rc, out) = run_tldr_in(
        repo,
        &["context", "lib/plug/conn.ex:assign", "--format", "json"],
    );
    assert_eq!(rc, 0, "elixir context rc != 0; stdout={}", out);
    let v = parse_json(&out);
    assert_eq!(entry_point(&v), "assign");
    assert!(func_count(&v) >= 1);
}

/// **ruby** — relative-path file:fn from inside rails-html-sanitizer.
#[test]
fn ruby_context_relative_file_func_sanitize() {
    let repo = "/tmp/repos/rails-html-sanitizer";
    if !Path::new(repo).exists() {
        return;
    }
    let (rc, out) = run_tldr_in(
        repo,
        &[
            "context",
            "lib/rails/html/sanitizer.rb:sanitize",
            "--format",
            "json",
        ],
    );
    assert_eq!(rc, 0, "ruby context rc != 0; stdout={}", out);
    let v = parse_json(&out);
    assert_eq!(entry_point(&v), "sanitize");
    assert!(func_count(&v) >= 1);
}

// ============================================================================
// Non-regression: the `--project` form (the long-standing canonical
// invocation) must keep returning the same callee counts. AGG15-2's
// fix is targeted at the file_filter early-return path; this test
// guards against the change accidentally diverting `--project`-form
// inputs into a different code path.
// ============================================================================

#[test]
fn nonreg_csharp_context_writetoken_via_project_returns_full_traversal() {
    let repo = "/tmp/repos/csharp-newtonsoft-bson-full";
    if !Path::new(repo).exists() {
        return;
    }
    let (rc, out) = run_tldr(&[
        "context",
        "WriteToken",
        "--project",
        repo,
        "--format",
        "json",
    ]);
    assert_eq!(rc, 0, "csharp --project rc != 0; stdout={}", out);
    let v = parse_json(&out);
    assert!(
        func_count(&v) >= 5,
        "csharp --project WriteToken: expected ≥ 5 functions, got {}",
        func_count(&v)
    );
}

#[test]
fn nonreg_js_context_render_via_project_with_file_filter_returns_full_traversal() {
    let repo = "/tmp/repos/express";
    if !Path::new(repo).exists() {
        return;
    }
    // Pin the file filter so the resolver picks `lib/application.js`
    // (Application.render with 6-function fan-out) deterministically.
    // Without `--file`, `render` is non-deterministically resolved
    // across the express tree (which has examples/view-constructor and
    // multiple integration tests defining the same name) — that
    // pre-existing edge case is orthogonal to AGG15-2 and tracked
    // elsewhere.
    let (rc, out) = run_tldr(&[
        "context",
        "render",
        "--project",
        repo,
        "--file",
        "lib/application.js",
        "--format",
        "json",
    ]);
    assert_eq!(rc, 0, "js --project rc != 0; stdout={}", out);
    let v = parse_json(&out);
    let n = func_count(&v);
    assert!(
        n >= 5,
        "js --project --file lib/application.js render: expected ≥ 5 functions, got {}; stdout={}",
        n,
        out
    );
}
