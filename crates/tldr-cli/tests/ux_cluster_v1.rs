//! ux-cluster-v1 — regression tests for the v0.4.2 UX cluster
//! (W-Q assertions VAL-UX-D2 / D3 / D5).
//!
//! Bugs covered:
//!
//! - **D3 — doctor missing ocaml**: `tldr doctor` listed 16 languages but
//!   OMITTED `ocaml` despite OCaml being supported by the rest of the
//!   toolchain (`Language::Ocaml`, `from_path` for `.ml/.mli`, etc).
//!   Fix: add an `ocaml` entry with merlin (type-checker) and
//!   ocaml-lsp-server (linter/LSP).
//!
//! - **D2 — semantic stderr misleading**: `SemanticIndex::build` printed
//!   `"Skipped N files (parse errors or unsupported)"` to stderr even
//!   when the skipped files were actually `Binary or hidden file`,
//!   `Unknown language for extension`, `Filtered out by language`, or
//!   `Read error` — none of which are "parse errors". Fix: rephrase to
//!   the accurate `"Skipped N files (binary, unknown language, or read
//!   errors)"`.
//!
//! - **D5 — swift importers misidentifies #if / preprocessor lines**:
//!   `tldr importers <swift-module> <repo>` returned preprocessor-
//!   conditional lines (`#if false`, `#if UnstableSortedCollections`)
//!   as the `import_statement`, because the default arm of
//!   `find_import_line` accepted ANY line containing the module name.
//!   Fix: require the line to actually look like a Swift import
//!   (`import …`, `@testable import …`, `@_spi(...) import …`) and
//!   never return preprocessor-conditional lines.

use assert_cmd::Command;
use serde_json::Value;
use std::path::Path;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

/// Skip helper: returns true and prints a notice when `path` doesn't
/// exist. Tests gate on real-repo presence per no-synthetic-fixtures-v1.
fn skip_if_missing(path: &str) -> bool {
    if !Path::new(path).exists() {
        eprintln!("[skip] {} not present", path);
        return true;
    }
    false
}

// =============================================================================
// D3 — doctor lists ocaml
// =============================================================================

#[test]
fn doctor_lists_ocaml() {
    // `tldr doctor -f json` returns a JSON map keyed by language name.
    // Before the fix, the map had 16 keys and `ocaml` was NOT one of them.
    // After the fix, `ocaml` is present with at least a type_checker entry
    // pointing at `merlin` (or `ocamlmerlin`).
    let out = tldr_cmd()
        .args(&["doctor", "-f", "json", "-q"])
        .output()
        .expect("tldr doctor must run");
    assert!(out.status.success(), "doctor exit: {:?}", out.status);

    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("doctor json parse failed: {e}; stdout was:\n{stdout}"));

    let obj = v.as_object().expect("doctor JSON top-level must be an object");
    assert!(
        obj.contains_key("ocaml"),
        "doctor must list `ocaml`. Keys were: {:?}",
        obj.keys().collect::<Vec<_>>()
    );

    // Sanity: the ocaml entry should advertise *some* tool. We don't
    // require the tools to be installed on the test machine, just that
    // the catalog references them.
    let ocaml = &obj["ocaml"];
    let tc = ocaml.get("type_checker");
    let linter = ocaml.get("linter");
    let has_tool = tc.map(|t| !t.is_null()).unwrap_or(false)
        || linter.map(|t| !t.is_null()).unwrap_or(false);
    assert!(
        has_tool,
        "ocaml entry must reference at least one tool, got: {ocaml}"
    );

    // The conventional OCaml tooling is merlin + ocaml-lsp-server.
    // We assert that at least one of those names appears somewhere in
    // the ocaml entry, so future renames stay deliberate.
    let serialized = serde_json::to_string(ocaml).unwrap();
    assert!(
        serialized.contains("merlin") || serialized.contains("ocaml-lsp"),
        "ocaml entry should mention merlin or ocaml-lsp-server; got: {serialized}"
    );
}

// =============================================================================
// D2 — semantic stderr text accuracy
// =============================================================================
//
// `tldr semantic` is feature-gated behind the `semantic` cargo feature,
// so the CLI sub-command isn't always present. The bug is in the source
// text of `crates/tldr-core/src/semantic/index.rs`, which is reachable
// regardless of build features. We therefore assert against the source
// to keep the test runnable in the default build profile.

#[test]
fn semantic_stderr_no_misleading_parse_errors_phrase() {
    // The chunker labels skipped files with one of these reasons (see
    // chunker.rs):
    //   - "Binary or hidden file"
    //   - "Unknown language for extension: <ext>"
    //   - "Filtered out by language (<lang>)"
    //   - "Read error: <io error>"
    // None of those are "parse errors". The user-facing summary in
    // index.rs must therefore NOT claim "parse errors or unsupported"
    // when the underlying cause is e.g. a language filter.
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("tldr-core")
        .join("src")
        .join("semantic")
        .join("index.rs");
    let src = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("could not read {}: {e}", path.display()));

    // Bug signature: the literal misleading phrase must be gone from the
    // user-facing eprintln (we still allow it in comments/docstrings so
    // archaeology stays possible, but the executable string must change).
    // We approximate "user-facing string" as: occurrences inside an
    // `eprintln!` / `println!` macro call.
    for line in src.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") {
            continue;
        }
        // The previous wording lived inside an eprintln! — fail if it
        // is still emitted at runtime.
        if line.contains("parse errors or unsupported") {
            panic!(
                "found misleading 'parse errors or unsupported' phrase still emitted in index.rs:\n{line}"
            );
        }
    }

    // Positive assertion: the new wording must describe the ACTUAL
    // skip reasons (binary / unknown language / read errors). We accept
    // any phrasing that mentions at least one of those true causes.
    let acceptable = [
        "binary",
        "unknown language",
        "unsupported language",
        "non-source",
        "read error",
    ];
    let lower = src.to_lowercase();
    assert!(
        acceptable.iter().any(|p| lower.contains(p)),
        "index.rs must mention the real skip reasons (binary / unknown language / read errors)"
    );
}

// =============================================================================
// D5 — swift importers skip preprocessor `#if` lines
// =============================================================================

#[test]
fn swift_importers_skips_preprocessor_if_lines() {
    let repo = "/tmp/repos/swift-collections";
    if skip_if_missing(repo) {
        return;
    }

    // `SortedCollections` is imported in many test files under
    // `Tests/SortedCollectionsTests/`. Several of those files wrap the
    // import in a `#if UnstableSortedCollections` block:
    //
    //   #if UnstableSortedCollections
    //   import _CollectionsTestSupport
    //   @_spi(Testing) @testable import SortedCollections
    //   …
    //   #endif
    //
    // The bug was: `find_import_line` would return the `#if …` line as
    // the `import_statement`, because the default arm accepted any line
    // containing the substring "SortedCollections". The fix must return
    // the actual `import` line.
    let out = tldr_cmd()
        .args(&["importers", "SortedCollections", repo, "-f", "json", "-q"])
        .output()
        .expect("tldr importers must run");
    assert!(
        out.status.success(),
        "importers exit: {:?}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("importers json parse failed: {e}; stdout was:\n{stdout}"));

    let importers = v["importers"].as_array().expect("importers array");
    assert!(
        !importers.is_empty(),
        "expected at least one importer for SortedCollections in swift-collections"
    );

    // Every reported `import_statement` must look like a real Swift
    // import line — it must contain the `import` keyword and must NOT
    // be a preprocessor directive.
    for imp in importers {
        let stmt = imp["import_statement"]
            .as_str()
            .expect("import_statement is a string");
        let trimmed = stmt.trim_start();
        assert!(
            !trimmed.starts_with("#if")
                && !trimmed.starts_with("#else")
                && !trimmed.starts_with("#elseif")
                && !trimmed.starts_with("#endif"),
            "import_statement must not be a preprocessor directive, got: {stmt:?} (file {:?})",
            imp["file"]
        );
        assert!(
            trimmed.contains("import"),
            "import_statement must contain the `import` keyword, got: {stmt:?}"
        );
    }
}
