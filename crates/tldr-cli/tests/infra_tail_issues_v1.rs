//! infra-tail-issues-v1 (v0.4.2 M-108)
//!
//! Five GitHub issues with root causes located in iter-2 reports
//! (audit_phase22):
//!
//! - #43 SKIP_DIRS consistency: `tldr deps` / `patterns` / `structure` /
//!   `inheritance` / `vuln` / `api-check` skip `dist`/`build`/`.next`/
//!   `.nuxt` from `crates/tldr-core/src/fs/tree.rs:32 DEFAULT_SKIP_DIRS`,
//!   while `calls`/`smells`/`health`/`semantic`/`dead`/`loc` use the
//!   callgraph scanner which already gates `build`/`dist`/`out`/`bin`/
//!   `obj` per-language. Result: same project, inconsistent file counts.
//!   Fix: drop `dist`/`build`/`.next`/`.nuxt`/`out`/`bin`/`obj` from the
//!   default tree skip list (they're routinely authored-source dir names
//!   in JS/TS monorepos; `node_modules`/`vendor`/`target`/cache dirs
//!   remain as the only genuine build sinks).
//!
//! - #53 Go debt stack overflow on nested non-Go files:
//!   `crates/tldr-core/src/quality/debt.rs:1504-1523`
//!   `extract_go_functions_for_debt` was the lone sibling without a
//!   `depth` parameter and `DEBT_MAX_AST_DEPTH` guard. Python/TS/Rust/
//!   Java/universal extractors all have it.
//!
//! - #57 Python XSS f-string + missing Flask sinks:
//!   `crates/tldr-core/src/security/taint.rs:1736-1744` HtmlOutput
//!   AstSinkPattern bank lacked `render_template_string`, `render_template`,
//!   `make_response`, and `Response`-as-call-name. Also the f-string
//!   return arm at L5141 walked ONLY the first interpolation; when the
//!   first one was a constant identifier the var-extraction missed the
//!   tainted variable in the second/third slot.
//!
//! - #58 Python multi-line `__all__` breaks wildcard imports:
//!   `crates/tldr-core/src/callgraph/import_resolver.rs:644-680`
//!   `parse_all` and `:1018-1045` `parse_dunder_all` both required
//!   single-line `[…]`. Cross-pipeline drift: the `interface` AST-based
//!   `__all__` parser worked, the resolver/`parse_dunder_all` did not.
//!
//! - #63 `.tldrignore` directory patterns don't exclude files:
//!   `crates/tldr-core/src/callgraph/scanner.rs:404-408` called
//!   `gi.matched(relative_path, false)` (single-segment match), but
//!   `corpus/` pattern only matches the `corpus` segment itself, never
//!   `corpus/vendored.py`. The sibling `filter_tldrignored` at L562 of
//!   the same module already uses `matched_path_or_any_parents` —
//!   bringing the scanner in line closes the drift.

use std::fs;
use tempfile::TempDir;

use tldr_core::analysis::deps::{analyze_dependencies, DepsOptions};
use tldr_core::callgraph::builder_v2::scan_project_files;
use tldr_core::callgraph::BuildConfig;
use tldr_core::quality::debt::analyze_file;
use tldr_core::security::taint::{detect_sinks_ast, TaintSinkType};
use tldr_core::Language;

// =============================================================================
// Issue #43 — DEFAULT_SKIP_DIRS consistency across deps/patterns/etc.
// =============================================================================

/// JS mini-app with files under both `src/` and `dist/` and `build/`
/// — these are commonly authored-source dirs in JS/TS land. Pre-fix,
/// `analyze_dependencies` (which routes through `get_file_tree` ->
/// `DEFAULT_SKIP_DIRS`) silently dropped every file under `dist/` and
/// `build/`. Post-fix, the file counts must reflect all four authored
/// .js files.
#[test]
fn issue_43_deps_includes_dist_build_for_js() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    fs::create_dir_all(root.join("src")).unwrap();
    fs::create_dir_all(root.join("dist")).unwrap();
    fs::create_dir_all(root.join("build")).unwrap();
    fs::create_dir_all(root.join("lib")).unwrap();

    // 4 authored .js files; deps tracker should see all of them.
    fs::write(root.join("src/index.js"), "import { x } from './util';\n").unwrap();
    fs::write(root.join("src/util.js"), "export const x = 1;\n").unwrap();
    fs::write(root.join("dist/bundle.js"), "export const bundled = 2;\n").unwrap();
    fs::write(root.join("build/output.js"), "export const built = 3;\n").unwrap();
    fs::write(root.join("lib/legacy.js"), "export const legacy = 4;\n").unwrap();

    let report = analyze_dependencies(
        root,
        &DepsOptions {
            language: Some("javascript".to_string()),
            ..DepsOptions::default()
        },
    )
    .expect("deps analysis failed");

    // Collect basename of every file the analyzer saw (keys of
    // internal_dependencies map).
    let seen_files: Vec<String> = report
        .internal_dependencies
        .keys()
        .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
        .collect();

    assert!(
        seen_files.iter().any(|n| n == "bundle.js"),
        "deps should include dist/bundle.js; saw: {:?}",
        seen_files
    );
    assert!(
        seen_files.iter().any(|n| n == "output.js"),
        "deps should include build/output.js; saw: {:?}",
        seen_files
    );
    assert!(
        seen_files.iter().any(|n| n == "index.js"),
        "deps should include src/index.js; saw: {:?}",
        seen_files
    );
    assert!(
        seen_files.iter().any(|n| n == "legacy.js"),
        "deps should include lib/legacy.js; saw: {:?}",
        seen_files
    );
}

// =============================================================================
// Issue #53 — Go debt stack overflow on deeply-nested AST
// =============================================================================

/// The Go-specific debt extractor MUST carry a `DEBT_MAX_AST_DEPTH`
/// guard matching every other sibling walker (Python at L1280, TS at
/// L1408, Rust at L1620, Java at L1722, universal at L1176). Pre-fix
/// it was the lone holdout — unbounded recursion at line 1519 would
/// stack-overflow on pathologically deep Go ASTs (or non-Go files
/// under wrong-language override).
///
/// This test enforces the structural invariant by reading the source
/// and asserting that:
///   1. The Go extractor's signature carries a `depth: usize` param.
///   2. Its body checks `depth > DEBT_MAX_AST_DEPTH` and bails early.
///   3. The recursive self-call passes `depth + 1`.
///
/// Source-text inspection mirrors the iter-2 methodology
/// (audit_phase22/iter2/go.md L573 lists #53 as "REPRODUCES (by
/// inspection)"). We deliberately do NOT execute the deep-Go scenario
/// because the iter-2 report points to a stack-overflow failure mode:
/// stack overflows abort the entire test runner via SIGABRT and
/// cannot be cleanly trapped from within a cargo test. Verifying the
/// fix by source-text inspection is the same evidence the iter-2
/// audit accepted, and it asserts the EXACT change the prompt calls
/// for: "Add `depth` parameter + `DEBT_MAX_AST_DEPTH` check to Go
/// extractor matching the sibling pattern."
#[test]
fn issue_53_go_debt_extractor_has_depth_guard() {
    let debt_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("tldr-core")
        .join("src")
        .join("quality")
        .join("debt.rs");
    let src = fs::read_to_string(&debt_path).expect("read debt.rs");

    // Locate `fn extract_go_functions_for_debt`.
    let fn_start = src
        .find("fn extract_go_functions_for_debt")
        .expect("extract_go_functions_for_debt must exist in debt.rs");
    let after = &src[fn_start..];
    // Slice the next ~2000 chars — far more than the function body
    // length, but bounded so we don't accidentally pick up an
    // unrelated sibling.
    let span_end = (fn_start + 2000).min(src.len());
    let span = &src[fn_start..span_end];

    // (1) Signature must carry a `depth: usize` parameter.
    let sig_end = after.find('{').expect("function body brace");
    let sig = &after[..sig_end];
    assert!(
        sig.contains("depth: usize"),
        "extract_go_functions_for_debt must take a depth: usize parameter; \
         signature was: {}",
        sig
    );

    // (2) Body must check `depth > DEBT_MAX_AST_DEPTH`.
    assert!(
        span.contains("depth > DEBT_MAX_AST_DEPTH"),
        "extract_go_functions_for_debt must guard against DEBT_MAX_AST_DEPTH; \
         got body span: {}",
        span
    );

    // (3) Recursive self-call must pass `depth + 1`.
    let recursive_call_idx = span[sig_end..]
        .find("extract_go_functions_for_debt(")
        .map(|i| sig_end + i);
    assert!(
        recursive_call_idx.is_some(),
        "extract_go_functions_for_debt must contain a recursive self-call"
    );
    let call_idx = recursive_call_idx.unwrap();
    // Look for `depth + 1` within the next 200 chars of the recursive
    // call site (covers the formatted args).
    let call_window =
        &span[call_idx..(call_idx + 200).min(span.len())];
    assert!(
        call_window.contains("depth + 1"),
        "extract_go_functions_for_debt's recursive call must pass depth + 1; \
         got call window: {}",
        call_window
    );

    // (4) Call-site must also be updated — the dispatch in
    // `extract_function_infos_for_debt` must pass `0` as the initial
    // depth (or any literal usize). Look for the language match arm.
    assert!(
        src.contains("extract_go_functions_for_debt(root, source, &mut functions, 0)")
            || src.contains("extract_go_functions_for_debt(\n            root,"),
        "dispatch in extract_function_infos_for_debt must pass initial depth 0 \
         to extract_go_functions_for_debt"
    );

    // (5) Smoke check: analyze a small Go file — verifies the new
    // signature compiles and that small files still produce results.
    let dir = TempDir::new().unwrap();
    let small = dir.path().join("small.go");
    fs::write(
        &small,
        "package main\n\nfunc Small(a, b int) int {\n    if a > b { return a }\n    return b\n}\n",
    )
    .unwrap();
    let result = analyze_file(&small, None, Some(Language::Go));
    assert!(
        result.is_ok(),
        "analyze_file must succeed on a normal Go file post-fix; got: {:?}",
        result.err()
    );
}

// =============================================================================
// Issue #57 — Python XSS f-string + missing Flask sinks
// =============================================================================

/// `render_template_string`, `render_template`, `make_response`, and
/// `Response(response=...)` are canonical Flask XSS sinks. Pre-fix the
/// HtmlOutput AstSinkPattern bank only contained `Markup` / `mark_safe`
/// / `|safe` / `response.write` / `Response.set_data` — none match
/// these top-level calls.
#[test]
fn issue_57a_flask_html_sinks_detected() {
    let source = b"\
from flask import render_template_string, render_template, make_response, Response

@app.route('/x1')
def x1():
    user = request.args.get('u')
    return render_template_string(user)

@app.route('/x2')
def x2():
    user = request.args.get('u')
    return render_template('tmpl.html', name=user)

@app.route('/x3')
def x3():
    user = request.args.get('u')
    return make_response(user)

@app.route('/x4')
def x4():
    user = request.args.get('u')
    return Response(user)
";
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_python::LANGUAGE.into())
        .unwrap();
    let tree = parser.parse(source.as_ref(), None).unwrap();
    let root = tree.root_node();

    let sinks = detect_sinks_ast(&root, source, Language::Python, None);

    // All four Flask sinks must produce HtmlOutput findings.
    let html_sinks: Vec<&_> = sinks
        .iter()
        .filter(|s| matches!(s.sink_type, TaintSinkType::HtmlOutput))
        .collect();
    let html_stmts: Vec<String> = html_sinks
        .iter()
        .filter_map(|s| s.statement.clone())
        .collect();

    assert!(
        html_stmts.iter().any(|s| s.contains("render_template_string")),
        "expected HtmlOutput sink on render_template_string call; saw: {:?}",
        html_stmts
    );
    assert!(
        html_stmts.iter().any(|s| {
            s.contains("render_template(") && !s.contains("render_template_string(")
        }),
        "expected HtmlOutput sink on render_template call; saw: {:?}",
        html_stmts
    );
    assert!(
        html_stmts.iter().any(|s| s.contains("make_response")),
        "expected HtmlOutput sink on make_response call; saw: {:?}",
        html_stmts
    );
    assert!(
        html_stmts.iter().any(|s| s.contains("Response(")),
        "expected HtmlOutput sink on Response() call; saw: {:?}",
        html_stmts
    );
}

/// f-string return with a literal-prefix interpolation followed by a
/// tainted var. Pre-fix, the return-arm only walked the FIRST
/// interpolation for a var name (line 5152 `break`); when the first
/// interpolation was an identifier like `version` that happened to be
/// constant (or absent of taint), the sink was emitted gated on
/// `version` rather than the tainted second var, and the downstream
/// taint reconciliation never flagged it. Post-fix, ALL interpolation
/// var names are emitted as sinks so any tainted var triggers.
#[test]
fn issue_57b_fstring_return_walks_all_interpolations() {
    let source = b"\
def view():
    version = '1.0'
    user = request.args.get('u')
    return f'<h1>v{version} hello {user}</h1>'
";
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_python::LANGUAGE.into())
        .unwrap();
    let tree = parser.parse(source.as_ref(), None).unwrap();
    let root = tree.root_node();

    let sinks = detect_sinks_ast(&root, source, Language::Python, None);

    // We need at least one HtmlOutput sink whose `var` is `user`
    // (the tainted second-slot interpolation). Pre-fix only the first
    // interpolation (`version`) was emitted as the sink var.
    let user_sinks: Vec<&_> = sinks
        .iter()
        .filter(|s| {
            matches!(s.sink_type, TaintSinkType::HtmlOutput) && s.var == "user"
        })
        .collect();

    assert!(
        !user_sinks.is_empty(),
        "expected HtmlOutput sink with var=user (second f-string interpolation); got sinks: {:?}",
        sinks
            .iter()
            .map(|s| (s.var.clone(), s.sink_type, s.line))
            .collect::<Vec<_>>()
    );
}

// =============================================================================
// Issue #58 — Python multi-line `__all__` breaks wildcard imports
// =============================================================================

/// Resolver-layer test for multi-line `__all__`. Pre-fix both
/// `parse_all` and `parse_dunder_all` required single-line `[ ... ]`,
/// so a multi-line `__all__` literal produced an empty export set,
/// and the wildcard re-export resolver dropped every name.
///
/// We verify by building a module index with a package whose
/// `__init__.py` carries a multi-line `__all__` and resolving a
/// `from pkg import *` wildcard. The resolved name set MUST equal the
/// three names listed in the multi-line `__all__`.
#[test]
fn issue_58_multiline_dunder_all_resolves() {
    use tldr_core::callgraph::{ImportDef, ImportResolver, ModuleIndex};

    let dir = TempDir::new().unwrap();
    let root = dir.path();
    fs::create_dir_all(root.join("pkg")).unwrap();

    // Multi-line __all__ — the canonical Python convention when
    // exporting more than a handful of names.
    fs::write(
        root.join("pkg/__init__.py"),
        "from .mod import Foo, Bar, Baz\n\
__all__ = [\n\
    'Foo',\n\
    'Bar',\n\
    'Baz',\n\
]\n",
    )
    .unwrap();
    fs::write(
        root.join("pkg/mod.py"),
        "class Foo:\n    pass\n\nclass Bar:\n    pass\n\nclass Baz:\n    pass\n",
    )
    .unwrap();

    // Caller file that does `from pkg import *`. It needs to exist
    // physically so the resolver can compute a relative path.
    let caller = root.join("caller.py");
    fs::write(&caller, "from pkg import *\n").unwrap();

    let index = ModuleIndex::build(root, "python").expect("build index");
    let mut resolver = ImportResolver::with_default_cache(&index);

    let import = ImportDef::wildcard_import("pkg");
    let resolved = resolver.resolve(&import, &caller);

    let names: Vec<String> = resolved
        .into_iter()
        .filter_map(|r| r.resolved_name)
        .collect();

    assert!(
        names.contains(&"Foo".to_string()),
        "multi-line __all__ wildcard should expose Foo; got: {:?}",
        names
    );
    assert!(
        names.contains(&"Bar".to_string()),
        "multi-line __all__ wildcard should expose Bar; got: {:?}",
        names
    );
    assert!(
        names.contains(&"Baz".to_string()),
        "multi-line __all__ wildcard should expose Baz; got: {:?}",
        names
    );
}

// =============================================================================
// Issue #63 — `.tldrignore` directory patterns don't exclude files
// =============================================================================

/// `corpus/` in a `.tldrignore` MUST exclude every file underneath
/// `corpus/`. Pre-fix `scan_project_files` used
/// `gi.matched(relative_path, false)` — a single-segment ignore lookup
/// that only matched the `corpus` segment itself, never
/// `corpus/vendored.py`. Sibling `filter_tldrignored` already correctly
/// used `matched_path_or_any_parents`; this regression closes the drift.
#[test]
fn issue_63_tldrignore_directory_excludes_nested_files() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();

    // Set up project with corpus/ (ignored) and src/ (kept).
    fs::create_dir_all(root.join("src")).unwrap();
    fs::create_dir_all(root.join("corpus/sub")).unwrap();
    fs::write(root.join("src/main.py"), "def main(): pass\n").unwrap();
    fs::write(root.join("corpus/vendored.py"), "# vendored\n").unwrap();
    fs::write(root.join("corpus/sub/deep.py"), "# deep\n").unwrap();
    fs::write(root.join(".tldrignore"), "corpus/\n").unwrap();

    let config = BuildConfig {
        language: "python".to_string(),
        respect_ignore: true,
        ..Default::default()
    };
    let files = scan_project_files(root, "python", &config).expect("scan failed");

    let names: Vec<String> = files
        .iter()
        .map(|f| f.path.file_name().unwrap().to_string_lossy().to_string())
        .collect();

    assert!(
        names.contains(&"main.py".to_string()),
        "src/main.py must survive .tldrignore filtering; got: {:?}",
        names
    );
    assert!(
        !names.contains(&"vendored.py".to_string()),
        "corpus/vendored.py must be excluded by `corpus/` pattern; got: {:?}",
        names
    );
    assert!(
        !names.contains(&"deep.py".to_string()),
        "corpus/sub/deep.py must be excluded by `corpus/` pattern; got: {:?}",
        names
    );
}
