//! cpp out-of-line method resolution (v0.5.0 FEATURE-1 d.7-2.1, REDESIGN).
//!
//! End-to-end proof that a TYPED receiver whose method is DEFINED OUT-OF-LINE
//! (`ReturnType Class::method() { ... }`) resolves through the real
//! extractor -> builder -> resolver pipeline.
//!
//! The C++ extractor records an out-of-line definition NOT as a class method but
//! as a bare free function whose name is the full qualified spelling
//! `Class::method` (colon-joined). The normal typed-receiver method resolver
//! keys on the dot form `Class.method` and on the class's AST-extracted `methods`
//! list, so before the additive resolver fallback it could never bind
//! `obj.method()` to the out-of-line def and the edge was dropped.
//!
//! The fix is a strictly ADDITIVE, fallback-only READ of the func_index (no
//! extractor change). These tests pin BOTH halves of the never-worse contract:
//!   * the typed receiver now resolves to the out-of-line `Class::method`;
//!   * an UNQUALIFIED intra-class direct call to a sibling out-of-line method
//!     (`other()` from another member of the same class) STILL resolves — the
//!     bare `Class::method` free-function entry it name-matches is left intact.

use std::path::Path;

use tempfile::TempDir;
use tldr_core::{build_project_call_graph, Language, ProjectCallGraph};

fn make_project(files: &[(&str, &str)]) -> TempDir {
    let dir = TempDir::new().expect("failed to create temp dir");
    for (name, content) in files {
        let path = dir.path().join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("failed to create parent dir");
        }
        std::fs::write(&path, content).expect("failed to write file");
    }
    dir
}

fn build_graph(dir: &Path) -> ProjectCallGraph {
    build_project_call_graph(dir, Language::Cpp, None, false)
        .unwrap_or_else(|e| panic!("cpp call graph build failed: {}", e))
}

const SOURCE: &str = r#"
struct Foo {
    void bar();
    void other();
    void caller();
};

void Foo::bar() {
}

void Foo::other() {
}

void Foo::caller() {
    other();
}

void run() {
    Foo f;
    f.bar();
}
"#;

/// The fix: a typed receiver `Foo f; f.bar();` resolves to the out-of-line
/// `Foo::bar` — rendered under its EXISTING bare colon name (no relabeling to a
/// dot key), so an edge `run -> Foo::bar` exists.
#[test]
fn cpp_out_of_line_typed_receiver_resolves() {
    let dir = make_project(&[("widget.cpp", SOURCE)]);
    let graph = build_graph(dir.path());

    let resolved_bar = graph
        .edges()
        .any(|e| e.src_func == "run" && e.dst_func == "Foo::bar");

    assert!(
        resolved_bar,
        "typed receiver `f.bar()` must resolve to out-of-line `Foo::bar`; edges: {:?}",
        graph
            .edges()
            .map(|e| (e.src_func.clone(), e.dst_func.clone()))
            .collect::<Vec<_>>()
    );
}

/// Never-worse guard: an UNQUALIFIED intra-class direct call `other()` made from
/// a sibling member (`Foo::caller`) STILL resolves to the sibling out-of-line
/// `Foo::other`. This is exactly what the reverted extractor approach broke by
/// removing the bare free-function entry; the additive resolver fallback leaves
/// the extractor untouched, so the direct-call edge is preserved.
#[test]
fn cpp_out_of_line_sibling_direct_call_still_resolves() {
    let dir = make_project(&[("widget.cpp", SOURCE)]);
    let graph = build_graph(dir.path());

    let resolved_other = graph
        .edges()
        .any(|e| e.src_func.contains("caller") && e.dst_func == "Foo::other");

    assert!(
        resolved_other,
        "unqualified intra-class direct call `other()` must still resolve to \
         `Foo::other`; edges: {:?}",
        graph
            .edges()
            .map(|e| (e.src_func.clone(), e.dst_func.clone()))
            .collect::<Vec<_>>()
    );
}
