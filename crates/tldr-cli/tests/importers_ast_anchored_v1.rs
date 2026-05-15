//! importers-ast-anchored-v1: AST-anchored line emission + relative-path
//! resolver + alias/docstring exclusion (v0.4.2 M-035).
//!
//! Pre-fix, the `importers` command had several emitter bugs:
//!
//! 1. **`line: 1` hardcoded for Go** — the find_import_line fallback returned
//!    `(1, "import {module}")` whenever the text-match scan didn't recognise
//!    the import idiom. Go's `import (...)` block (where the module string is
//!    inside parentheses on its own line, not on the same line as the
//!    `import` keyword) tripped this. Result: every Go importer entry pinned
//!    to line 1.
//!
//! 2. **CPP relative includes missed** — `#include "../foo.h"` was not
//!    matched against a query for `foo.h`. The exact-match-only rule for
//!    Cpp/C in `module_matches` only succeeded when the import module
//!    equalled the target string.
//!
//! 3. **CSharp `using A = B.C;` aliases pinned line 1 / wrong line** — the
//!    text-match scan in `find_import_line` returned the FIRST line whose
//!    substring matched the module name. In a file containing both a
//!    type-alias `using Assert = Newtonsoft.Json.Bson.Tests.XUnitAssert;`
//!    on line 36 AND a real `using Newtonsoft.Json.Bson;` on line 40, a
//!    query for `Newtonsoft.Json.Bson` returned the alias line (36) — the
//!    qualified namespace appears in the RHS of the alias and is a
//!    substring of the line. Also, the alias-target's `Newtonsoft.Json.
//!    Bson.Tests.XUnitAssert` was not recognised as a submodule of
//!    `Newtonsoft.Json.Bson` (no Java/Scala-style submodule rule was
//!    registered for CSharp), so the matching never even reached the
//!    real import line for some queries.
//!
//! 4. **Elixir docstring false positives** — the importers emitter walked
//!    the file's text lines looking for the module substring. Plug's
//!    `lib/plug/builder.ex` has a doc comment that mentions `Plug.Conn`
//!    («`Plug.Builder` imports the `Plug.Conn` module so functions like
//!    `send_resp/3`...») on line 29; the text-match emitter surfaced that
//!    line as the import statement even though the AST has no
//!    `import Plug.Conn` call in that file at all. Also: `defmodule
//!    Plug.Conn.Adapter do` on line 1 was emitted as an importer, but
//!    that's a module DEFINITION (the defining file), not an import of
//!    the module.
//!
//! Fix shape: AST-anchored search. Each AST extractor now populates
//! `ImportInfo.line` from the import node's `start_position().row + 1`.
//! The importers emitter consumes that directly instead of substring-
//! scanning the text lines. CPP gains relative-path resolution (`../foo.h`
//! against the importer file's directory canonicalises to `foo.h`).
//! CSharp aliases (`using A = B.C;`) no longer make their alias name
//! `A` matchable — only the RHS module `B.C` matches.

use assert_cmd::Command;
use serde_json::Value;
use std::io::Write;
use std::path::Path;
use tempfile::TempDir;

/// Run `tldr importers <module> <path> --lang <lang> -q -f json` and return
/// the parsed JSON envelope.
fn run_importers(module: &str, path: &Path, lang: &str) -> Value {
    let out = Command::cargo_bin("tldr")
        .expect("tldr binary")
        .args([
            "importers",
            module,
            path.to_str().unwrap(),
            "--lang",
            lang,
            "-q",
            "-f",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    serde_json::from_slice(&out).expect("importers output is JSON")
}

/// Write a file at `dir/relpath` with `content`. Creates intermediate dirs.
fn write_file(dir: &Path, relpath: &str, content: &str) {
    let full = dir.join(relpath);
    if let Some(parent) = full.parent() {
        std::fs::create_dir_all(parent).expect("create parent dir");
    }
    let mut f = std::fs::File::create(&full).expect("create file");
    f.write_all(content.as_bytes()).expect("write file");
}

// =============================================================================
// Go: line must NOT be hardcoded to 1
// =============================================================================
//
// Pre-fix repro: every Go importer entry returned line=1 because the
// text-match fallback in `find_import_line` returns `(1, "import {module}")`
// when no Go-shaped import line is found (e.g. inside an `import (...)`
// block where the module string is on its own line, not the line starting
// with `import`).
#[test]
fn go_importer_line_is_ast_anchored_not_one() {
    let dir = TempDir::new().expect("tempdir");
    write_file(
        dir.path(),
        "main.go",
        "package main\n\
         \n\
         // some leading comment lines\n\
         // another comment line\n\
         // yet another comment line\n\
         \n\
         import (\n\
         \t\"fmt\"\n\
         \t\"net/http\"\n\
         )\n\
         \n\
         func main() {\n\
         \tfmt.Println(\"hello\")\n\
         \thttp.ListenAndServe(\":8080\", nil)\n\
         }\n",
    );

    let v = run_importers("net/http", dir.path(), "go");
    let importers = v["importers"].as_array().expect("importers array");
    assert_eq!(importers.len(), 1, "expected 1 Go importer, got {:?}", v);
    let line = importers[0]["line"].as_u64().expect("line is integer");
    // The "net/http" string lives on line 9 of main.go (inside the import
    // block, NOT on the `import` keyword line).
    assert!(
        line > 1,
        "Go importer line should be AST-anchored to where the module string lives (~line 9), got line={}",
        line
    );
    assert_eq!(
        line, 9,
        "Go importer line should be the import_spec line (9), got line={}",
        line
    );
}

// =============================================================================
// CPP: #include "../subdir/foo.h" — relative-path resolution
// =============================================================================
//
// Pre-fix: a query for `foo.h` against a file containing `#include
// "../subdir/foo.h"` returned no importers — exact-match-only rule.
// Post-fix: the resolver canonicalises the relative include against the
// importer file's directory and recognises it as a reference to the
// header file `foo.h`.
#[test]
fn cpp_importer_relative_include_resolves() {
    let dir = TempDir::new().expect("tempdir");
    write_file(dir.path(), "subdir/foo.h", "#pragma once\nvoid foo();\n");
    write_file(
        dir.path(),
        "other/caller.cpp",
        "// header lines for spacing\n\
         // another line\n\
         #include \"../subdir/foo.h\"\n\
         \n\
         int main() { foo(); return 0; }\n",
    );

    // Query the bare header name. Pre-fix this returns 0 importers.
    let v = run_importers("foo.h", dir.path(), "cpp");
    let importers = v["importers"].as_array().expect("importers array");
    assert!(
        !importers.is_empty(),
        "expected ../subdir/foo.h to match query `foo.h`, got {:?}",
        v
    );
    let line = importers[0]["line"].as_u64().expect("line is integer");
    assert_eq!(
        line, 3,
        "CPP importer line should be 3 (line of #include), got line={}",
        line
    );
}

// =============================================================================
// CSharp: `using A = B.C;` alias must NOT match query `A`
// and a real `using B.C;` lower in the file should be the match line for
// query `B.C`.
// =============================================================================
//
// Pre-fix double bug:
//   (a) A query for `Newtonsoft.Json.Bson` matched the alias line at 36
//       (`using Assert = Newtonsoft.Json.Bson.Tests.XUnitAssert;`) because
//       the text-match scan returned the first substring hit.
//   (b) A query for the alias name `Assert` returned the alias declaration
//       as if `Assert` were itself an imported module — confusing the
//       alias target with the alias name.
#[test]
fn csharp_alias_excluded_and_real_using_line_anchored() {
    let dir = TempDir::new().expect("tempdir");
    let src = "// header comment\n\
              // more lines\n\
              // padding to push usings down\n\
              // padding\n\
              // padding\n\
              using Assert = Newtonsoft.Json.Bson.Tests.XUnitAssert;\n\
              using Newtonsoft.Json.Bson;\n\
              \n\
              namespace Foo {\n\
              \tpublic class Bar { }\n\
              }\n";
    write_file(dir.path(), "BsonTests.cs", src);

    // (a) Query the real namespace. Must point at line 7 (the real
    // `using Newtonsoft.Json.Bson;`), NOT line 6 (the alias).
    let v = run_importers("Newtonsoft.Json.Bson", dir.path(), "csharp");
    let importers = v["importers"].as_array().expect("importers array");
    assert_eq!(
        importers.len(),
        1,
        "expected 1 CSharp importer, got {:?}",
        v
    );
    let line = importers[0]["line"].as_u64().expect("line is integer");
    assert_eq!(
        line, 7,
        "CSharp importer line should anchor on the real `using Newtonsoft.Json.Bson;` (line 7), got line={}",
        line
    );
    let stmt = importers[0]["import_statement"].as_str().unwrap_or("");
    assert!(
        !stmt.contains("Assert ="),
        "CSharp importer statement should NOT be the alias line, got {:?}",
        stmt
    );

    // (b) Query the alias name `Assert`. The alias is a local binding;
    // `Assert` is not an imported module. Must return zero importers.
    let v2 = run_importers("Assert", dir.path(), "csharp");
    let importers2 = v2["importers"].as_array().expect("importers array");
    assert!(
        importers2.is_empty(),
        "CSharp alias name `Assert` should NOT match as an importer of Assert, got {:?}",
        v2
    );
}

// =============================================================================
// Elixir: defmodule line and docstring mentions must NOT count as importers.
// =============================================================================
//
// Pre-fix repros (real Plug repo, lib/plug/conn/adapter.ex line 1):
//   line=1  → `defmodule Plug.Conn.Adapter do`     (defmodule = DEFINITION
//                                                    of a SUBmodule, not an
//                                                    import of Plug.Conn)
//   line=29 → ```Plug.Builder` imports the `Plug.Conn` module so functions
//             like `send_resp/3` ``` (a DOC string mentioning Plug.Conn)
//
// Post-fix: only AST-anchored `import`/`alias`/`use`/`require` call nodes
// in the file count. defmodule and docstring text mentions don't count.
#[test]
fn elixir_docstring_and_defmodule_excluded() {
    let dir = TempDir::new().expect("tempdir");

    // File A: defmodule whose name contains `Plug.Conn` as a prefix and
    // an `alias Plug.Conn` call on a non-line-1 line. Pre-fix the
    // importers emitter returned line=1 with `defmodule Plug.Conn.Adapter
    // do` because find_import_line's catch-all surfaced the first line
    // containing the module substring — that's the defmodule line, not
    // the alias line. Post-fix the AST-anchored line points at the alias.
    //
    // Layout:
    //   1: defmodule Plug.Conn.Adapter do
    //   2: \t@moduledoc """
    //   3: \tThe adapter for Plug.Conn.
    //   4: \t"""
    //   5: \talias Plug.Conn        <-- ast-anchored row
    //   6: end
    write_file(
        dir.path(),
        "lib/adapter.ex",
        "defmodule Plug.Conn.Adapter do\n\
         \t@moduledoc \"\"\"\n\
         \tThe adapter for Plug.Conn.\n\
         \t\"\"\"\n\
         \talias Plug.Conn\n\
         end\n",
    );

    // File B: docstring mentions `Plug.Conn` but no real import/alias/
    // require/use call. Pre-fix the emitter returned this file with the
    // docstring text as the import_statement (because find_import_line's
    // catch-all returns the first text-substring match). Post-fix this
    // file is NOT an importer of Plug.Conn at all.
    write_file(
        dir.path(),
        "lib/builder.ex",
        "defmodule Plug.Builder do\n\
         \t@moduledoc \"\"\"\n\
         \t`Plug.Builder` imports the `Plug.Conn` module so functions like\n\
         \t`send_resp/3` are imported into the user module by default.\n\
         \t\"\"\"\n\
         end\n",
    );

    // File C: real `import Plug.Conn` on a non-line-1 line. This is the
    // ONLY legitimate importer of `Plug.Conn` in this fixture.
    write_file(
        dir.path(),
        "lib/basic_auth.ex",
        "defmodule Plug.BasicAuth do\n\
         \t@moduledoc \"Basic auth plug.\"\n\
         \n\
         \timport Plug.Conn\n\
         \n\
         \tdef call(conn, _opts), do: conn\n\
         end\n",
    );

    let v = run_importers("Plug.Conn", dir.path(), "elixir");
    let importers = v["importers"].as_array().expect("importers array");

    let files: Vec<&str> = importers
        .iter()
        .map(|imp| imp["file"].as_str().unwrap_or(""))
        .collect();

    // basic_auth.ex has a real `import Plug.Conn` — must appear.
    assert!(
        files.iter().any(|f| f.ends_with("basic_auth.ex")),
        "expected basic_auth.ex among importers, got {:?}",
        files
    );
    // builder.ex has only a docstring mention — must NOT appear.
    assert!(
        !files.iter().any(|f| f.ends_with("builder.ex")),
        "docstring mentioning Plug.Conn is NOT an importer of Plug.Conn, got {:?}",
        files
    );

    // adapter.ex has a real `alias Plug.Conn` on line 6, AND a defmodule
    // header on line 1. Pre-fix, the emitter reported line=1 (the
    // defmodule line, picked up by the text-substring catch-all) and the
    // import_statement was the defmodule text. Post-fix, the line points
    // at the AST-anchored alias call (line 6).
    let adapter = importers
        .iter()
        .find(|imp| imp["file"].as_str().unwrap_or("").ends_with("adapter.ex"))
        .expect("adapter.ex among importers (has real alias Plug.Conn)");
    let adapter_line = adapter["line"].as_u64().expect("line is integer");
    assert_eq!(
        adapter_line, 5,
        "Elixir adapter.ex import line should be the AST-anchored `alias Plug.Conn` line (5), not the defmodule line, got line={}",
        adapter_line
    );
    let adapter_stmt = adapter["import_statement"].as_str().unwrap_or("");
    assert!(
        !adapter_stmt.contains("defmodule"),
        "Elixir adapter.ex import statement should NOT be the defmodule line, got {:?}",
        adapter_stmt
    );

    // basic_auth.ex import line must be AST-anchored (line 4), not 1.
    let basic_auth = importers
        .iter()
        .find(|imp| {
            imp["file"]
                .as_str()
                .unwrap_or("")
                .ends_with("basic_auth.ex")
        })
        .expect("basic_auth.ex importer");
    let line = basic_auth["line"].as_u64().expect("line is integer");
    assert_eq!(
        line, 4,
        "Elixir import line should be AST-anchored (line 4), got line={}",
        line
    );
}

// =============================================================================
// Python: sanity check — line must come from AST, not always 1.
// =============================================================================
#[test]
fn python_importer_line_is_ast_anchored() {
    let dir = TempDir::new().expect("tempdir");
    write_file(
        dir.path(),
        "consumer.py",
        "\"\"\"Module docstring on line 1.\n\
         services.auth is mentioned here but this is a docstring, NOT an import.\n\
         \"\"\"\n\
         \n\
         import os\n\
         import sys\n\
         from services.auth import authenticate\n\
         \n\
         def go(): pass\n",
    );
    // Provide a defining file too so module resolution works on any
    // hypothetical resolver downstream.
    write_file(dir.path(), "services/auth.py", "def authenticate(): pass\n");
    write_file(dir.path(), "services/__init__.py", "");

    let v = run_importers("services.auth", dir.path(), "python");
    let importers = v["importers"].as_array().expect("importers array");
    let consumer = importers
        .iter()
        .find(|imp| {
            imp["file"]
                .as_str()
                .unwrap_or("")
                .ends_with("consumer.py")
        })
        .expect("consumer.py among importers");
    let line = consumer["line"].as_u64().expect("line is integer");
    // The `from services.auth import authenticate` is on line 7. Pre-fix
    // a flawed scan could return line 2 (docstring substring match);
    // post-fix the AST node anchors line 7.
    assert_eq!(
        line, 7,
        "Python importer line should anchor on the real `from services.auth import authenticate` (line 7), got line={}",
        line
    );
}
