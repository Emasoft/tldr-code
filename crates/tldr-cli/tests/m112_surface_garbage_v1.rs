//! m112-surface-garbage-cleanup-v1 (v0.4.2 M-112)
//!
//! Wave 17e: four cross-language surface/interface garbage filters. The
//! iter-2 audit observed:
//!
//!   1. **C surface** on `/tmp/repos/c-sds` emitted line-noise as
//!      "function" entries — block-comment continuation lines (`Copyright`,
//!      license boilerplate, ALL-CAPS legalese), `__attribute__` GCC
//!      attribute directives, and macro identifiers (`SDS_HDR`,
//!      `SDS_HDR_VAR`, `SDS_TYPE_5_LEN`, even `|` and `printf`) all
//!      surfaced as APIs because the header extractor used a line-based
//!      prototype guesser that didn't track block-comment state, didn't
//!      reject `__attribute__`, and didn't distinguish macro calls from
//!      real declarations.
//!
//!   2. **C++ surface** on `cpp-tinyxml2/tinyxml2.h` emitted qualified
//!      names with stray `..` prefixes when the line-based parser tripped
//!      on doc-comment continuation text containing identifiers like
//!      `XMLDocument::DeepCopy()` — the qualifier was lost (block-comment
//!      contents were treated as code) and synthesized names like
//!      `..Set` appeared at module level. The fix is to track block
//!      comment state so doc-comment bodies don't get parsed as
//!      declarations.
//!
//!   3. **Ruby inheritance** on `/tmp/repos/ruby-rubocop` previously
//!      reported `parent: "<"` for a handful of classes when the
//!      superclass-name extractor walked `superclass` node children and
//!      took the first text token (the literal `<` punctuation).
//!      `inheritance/ruby.rs::extract_superclass_name` already matches
//!      only `constant` / `scope_resolution` children, but this suite
//!      pins the behaviour so future refactors can't regress.
//!
//!   4. **Swift surface** on `/tmp/repos/swift-collections` must never
//!      emit API entries with empty names or null line numbers. The
//!      `qualified_name` last segment must always be a real identifier
//!      (or operator like `==`/`<<`), and `location.line` must always
//!      be a positive integer.
//!
//! Each acceptance gates on the corresponding `/tmp/repos/<corpus>`
//! being present and skips with a clear message otherwise so the suite
//! stays portable across CI environments that haven't cloned the
//! reference fixtures.

use assert_cmd::Command;
use serde_json::Value;
use std::path::Path;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

fn run_json(args: &[&str]) -> Option<Value> {
    let output = tldr_cmd().args(args).output().expect("run tldr");
    let stdout = String::from_utf8(output.stdout).ok()?;
    serde_json::from_str(&stdout).ok()
}

// ============================================================================
// Acceptance 1 — C surface on c-sds emits ZERO names matching the
// known garbage patterns: block-comment leakage (`Copyright`, ALL-CAPS
// legalese), `__attribute__` directives, the pipe operator `|`, and
// preprocessor-macro identifier leakage (`SDS_HDR`, `SDS_HDR_VAR`,
// `SDS_TYPE_5_LEN`, `printf`).
// ============================================================================

#[test]
fn test_m112_c_surface_no_comment_or_attribute_garbage() {
    let corpus = Path::new("/tmp/repos/c-sds");
    if !corpus.exists() {
        eprintln!(
            "skipping test_m112_c_surface_no_comment_or_attribute_garbage: \
             corpus {} missing",
            corpus.display()
        );
        return;
    }

    let json = run_json(&["surface", "/tmp/repos/c-sds", "--format", "json"])
        .expect("c-sds surface should return valid JSON");
    let apis = json
        .get("apis")
        .and_then(|v| v.as_array())
        .expect(".apis[] must be present");

    let mut names: Vec<String> = apis
        .iter()
        .filter_map(|api| api.get("qualified_name").and_then(|v| v.as_str()))
        .map(|s| s.to_string())
        .collect();

    // Each api's symbol is the last `.`-segment of qualified_name.
    let symbols: Vec<String> = names
        .iter()
        .map(|q| q.rsplit('.').next().unwrap_or(q).to_string())
        .collect();

    // Comment-leakage and attribute garbage MUST be gone.
    let comment_leakage: Vec<&String> = symbols
        .iter()
        .filter(|s| {
            *s == "Copyright"
                || *s == "INCLUDING"
                || *s == "WARRANTIES"
                || *s == "EXEMPLARY"
                || *s == "LIABILITY"
                || *s == "DAMAGES"
                || *s == "DIRECT"
                || *s == "INDIRECT"
                || *s == "INCIDENTAL"
                || *s == "SPECIAL"
                || *s == "DATA"
                || *s == "OTHERWISE"
                || *s == "CONTRACT"
                || *s == "USE"
                || *s == "TO"
        })
        .collect();
    assert!(
        comment_leakage.is_empty(),
        "C surface leaked block-comment text as function names: {:?}",
        comment_leakage
    );

    // `__attribute__` directives MUST NOT be reported as functions.
    assert!(
        !symbols.iter().any(|s| s == "__attribute__"),
        "C surface emitted `__attribute__` GCC attribute as a function: {:?}",
        symbols
            .iter()
            .filter(|s| s == &"__attribute__")
            .collect::<Vec<_>>()
    );

    // Pipe operator MUST NOT appear as a "function".
    assert!(
        !symbols.iter().any(|s| s == "|"),
        "C surface emitted `|` pipe operator as a function"
    );

    // Macro identifiers (preprocessor #define names invoked from inline
    // function bodies) MUST NOT surface as functions.
    let macro_leakage: Vec<&String> = symbols
        .iter()
        .filter(|s| {
            *s == "SDS_HDR"
                || *s == "SDS_HDR_VAR"
                || *s == "SDS_TYPE_5_LEN"
                || *s == "printf"
        })
        .collect();
    assert!(
        macro_leakage.is_empty(),
        "C surface emitted preprocessor-macro identifiers as functions: {:?}",
        macro_leakage
    );

    // Names with a leading `..` or `.` are corrupt qualified_names where
    // the module path collapsed to empty.
    names.sort();
    names.dedup();
    let dotted: Vec<&String> = names
        .iter()
        .filter(|n| n.starts_with("..") || n.starts_with('.'))
        .collect();
    assert!(
        dotted.is_empty(),
        "C surface emitted qualified_names with leading dots: {:?}",
        dotted
    );

    // Sanity floor: at least a few REAL sds public entries must remain.
    let real_count = symbols.iter().filter(|s| s.starts_with("sds")).count();
    assert!(
        real_count >= 10,
        "C surface lost real sds* entries (only {} remain) — \
         garbage filter may be over-broad",
        real_count
    );
}

// ============================================================================
// Acceptance 2 — C++ surface on tinyxml2.h emits ZERO qualified_names
// with a leading `..` (the symptom of a lost class/namespace qualifier
// when the line-based parser tripped on doc-comment contents).
// ============================================================================

#[test]
fn test_m112_cpp_surface_no_dot_prefix_or_doc_comment_leakage() {
    let header = Path::new("/tmp/repos/cpp-tinyxml2/tinyxml2.h");
    if !header.exists() {
        eprintln!(
            "skipping test_m112_cpp_surface_no_dot_prefix_or_doc_comment_leakage: \
             {} missing",
            header.display()
        );
        return;
    }

    let json = run_json(&[
        "surface",
        "/tmp/repos/cpp-tinyxml2/tinyxml2.h",
        "--format",
        "json",
    ])
    .expect("cpp tinyxml2.h surface should return valid JSON");
    let apis = json
        .get("apis")
        .and_then(|v| v.as_array())
        .expect(".apis[] must be present");

    let qualified: Vec<&str> = apis
        .iter()
        .filter_map(|api| api.get("qualified_name").and_then(|v| v.as_str()))
        .collect();

    // Any qualified_name with a leading `..` indicates a lost parent
    // qualifier — the M-112 symptom (`..Set`, `..XMLDocument`, …).
    let dotted: Vec<&str> = qualified
        .iter()
        .copied()
        .filter(|q| q.starts_with("..") || q.contains("..") || q.starts_with('.'))
        .filter(|q| !q.starts_with("../")) // path artifacts, not name corruption
        .collect();
    assert!(
        dotted.is_empty(),
        "C++ surface emitted qualified_names with stray `..` prefix \
         or empty-segment dots: {:?}",
        dotted
    );

    // Doc-comment-leakage names: tinyxml2.h has a doc comment near line
    // 896 referencing `XMLDocument::DeepCopy()`. Before M-112 that text
    // was parsed as a free function `XMLDocument::DeepCopy`. The fixed
    // line parser tracks block-comment state, so:
    //   - the symbol must NOT include `::` (we only emit unqualified
    //     names; `::` survival means the parser walked doc-comment text).
    //   - the symbol must NOT contain unmatched operator/cast tokens
    //     like `&&`, `=` alone, or `>`.
    let doc_leakage: Vec<&str> = qualified
        .iter()
        .copied()
        .filter(|q| {
            let last = q.rsplit('.').next().unwrap_or(q);
            last.contains("::")
                || last == "&&"
                || last == "="
                || last == "pattern\""
                || last.contains('>')
        })
        .collect();
    assert!(
        doc_leakage.is_empty(),
        "C++ surface leaked doc-comment / operator tokens as function names: {:?}",
        doc_leakage
    );

    // Sanity floor: tinyxml2 must still expose real XML* class entries.
    let real_xml = qualified.iter().filter(|q| q.contains("XML")).count();
    assert!(
        real_xml >= 5,
        "C++ surface lost real XML* entries (only {} remain) — \
         block-comment filter may be over-broad",
        real_xml
    );
}

// ============================================================================
// Acceptance 3 — Ruby inheritance on rubocop emits ZERO `parent: "<"`
// entries. tree-sitter-ruby `superclass` nodes carry `<` as a discrete
// punctuation token; the extractor must walk only `constant` /
// `scope_resolution` children.
// ============================================================================

#[test]
fn test_m112_ruby_inheritance_no_lt_token_as_parent() {
    let corpus = Path::new("/tmp/repos/ruby-rubocop");
    if !corpus.exists() {
        eprintln!(
            "skipping test_m112_ruby_inheritance_no_lt_token_as_parent: \
             corpus {} missing",
            corpus.display()
        );
        return;
    }

    let json = run_json(&[
        "inheritance",
        "/tmp/repos/ruby-rubocop",
        "--format",
        "json",
    ])
    .expect("rubocop inheritance should return valid JSON");

    // The schema uses `edges[]` (not `relations[]`); pin both shapes
    // defensively.
    let edges = json
        .get("edges")
        .or_else(|| json.get("relations"))
        .and_then(|v| v.as_array())
        .expect("inheritance must report .edges[] or .relations[]");

    let parents: Vec<&str> = edges
        .iter()
        .filter_map(|e| e.get("parent").and_then(|v| v.as_str()))
        .collect();

    // The literal `<` punctuation must NEVER appear as a parent class.
    let lt_parents: Vec<&&str> = parents.iter().filter(|p| **p == "<").collect();
    assert!(
        lt_parents.is_empty(),
        "Ruby inheritance reported {} `<` token(s) as parent class names",
        lt_parents.len()
    );

    // Other punctuation/operator tokens must also never surface as parents.
    let punct: Vec<&&str> = parents
        .iter()
        .filter(|p| matches!(**p, ">" | "::" | "=" | "," | "(" | ")"))
        .collect();
    assert!(
        punct.is_empty(),
        "Ruby inheritance reported punctuation token(s) as parent: {:?}",
        punct
    );

    // Sanity floor: rubocop has a deep class tree, so at least 50 edges
    // must remain.
    assert!(
        edges.len() >= 50,
        "Ruby inheritance scan returned only {} edges — filter may be over-broad",
        edges.len()
    );
}

// ============================================================================
// Acceptance 4 — Swift surface on swift-collections emits ZERO entries
// with an empty / missing name or a missing line number. tree-sitter-swift
// occasionally returns identifier-less function declarations (anonymous
// or parse-error nodes); the extractor must filter those out and must
// always populate `location.line` from the AST node's start position.
// ============================================================================

#[test]
fn test_m112_swift_surface_no_null_name_or_line() {
    let corpus = Path::new("/tmp/repos/swift-collections");
    if !corpus.exists() {
        eprintln!(
            "skipping test_m112_swift_surface_no_null_name_or_line: \
             corpus {} missing",
            corpus.display()
        );
        return;
    }

    let json = run_json(&[
        "surface",
        "/tmp/repos/swift-collections",
        "--format",
        "json",
    ])
    .expect("swift-collections surface should return valid JSON");
    let apis = json
        .get("apis")
        .and_then(|v| v.as_array())
        .expect(".apis[] must be present");

    assert!(
        !apis.is_empty(),
        "swift surface returned zero APIs — extractor regression"
    );

    let mut bad_name = 0usize;
    let mut bad_line = 0usize;
    let mut bad_examples: Vec<String> = Vec::new();
    for api in apis.iter() {
        let qn = api
            .get("qualified_name")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let symbol = qn.rsplit('.').next().unwrap_or("");
        if qn.is_empty() || symbol.is_empty() {
            bad_name += 1;
            if bad_examples.len() < 5 {
                bad_examples.push(format!("name-empty: {:?}", api));
            }
        }
        let line = api
            .get("location")
            .and_then(|loc| loc.get("line"))
            .and_then(|v| v.as_u64());
        if line.is_none() || line == Some(0) {
            bad_line += 1;
            if bad_examples.len() < 5 {
                bad_examples.push(format!("line-null: {:?}", api));
            }
        }
    }
    assert!(
        bad_name == 0 && bad_line == 0,
        "Swift surface emitted {} entries with empty name and {} with null/zero line \
         (sample: {:?})",
        bad_name,
        bad_line,
        bad_examples
    );

    // Sanity floor: real swift-collections API count should be ≥ 100.
    assert!(
        apis.len() >= 100,
        "Swift surface returned only {} entries — extractor regression",
        apis.len()
    );
}
