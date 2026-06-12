//! fix-cl-1-v1 (v0.5.0 CL-1): call-graph caller call-site line must be
//! preserved on every `CrossFileCallEdge`.
//!
//! Regression: `tldr explain` / `tldr coupling` reported `line: 0` for every
//! call-graph-resolved caller/callee because `CrossFileCallEdge` dropped the
//! call-site line carried by the underlying `CallSite`. The line was only
//! recoverable via a fragile references/AST-rescan fallback. These tests pin
//! that the builder populates `call_line` on resolved edges, that the
//! structural dedup key still collapses multiple call sites into one edge,
//! and that `call_line` is excluded from edge identity (Eq/Hash).

use std::path::PathBuf;

use super::cross_file_types::{CallType, CrossFileCallEdge};

/// The structural identity of an edge (src/dst file+func+call_type) must NOT
/// include `call_line` — two call sites for the same caller->callee pair are
/// one logical edge. Adding the line as a tracked field but keeping it out of
/// Eq/Hash preserves the existing dedup contract.
#[test]
fn call_line_is_excluded_from_edge_identity() {
    let base = CrossFileCallEdge {
        src_file: PathBuf::from("a.c"),
        src_func: "caller".to_string(),
        dst_file: PathBuf::from("b.c"),
        dst_func: "callee".to_string(),
        call_type: CallType::Direct,
        via_import: None,
        call_line: Some(10),
    };
    let other_line = CrossFileCallEdge {
        call_line: Some(99),
        ..base.clone()
    };
    let no_line = CrossFileCallEdge {
        call_line: None,
        ..base.clone()
    };

    // Same structural key => equal regardless of call_line.
    assert_eq!(base, other_line);
    assert_eq!(base, no_line);

    // And they hash to the same bucket (HashSet dedups them to one entry).
    use std::collections::HashSet;
    let mut set: HashSet<CrossFileCallEdge> = HashSet::new();
    set.insert(base.clone());
    set.insert(other_line.clone());
    set.insert(no_line.clone());
    assert_eq!(
        set.len(),
        1,
        "edges differing only by call_line must dedup to one structural edge"
    );
}

/// End-to-end: a project call graph built from a tiny C project must carry the
/// real call-site line on the resolved cross-file edge, NOT 0.
#[test]
fn project_graph_edges_carry_call_site_line_c() {
    use crate::build_project_call_graph;
    use crate::types::Language;

    let dir = std::env::temp_dir().join(format!("tldr_cl1_test_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");

    // callee.c defines `make_room`; caller.c calls it on a known line.
    std::fs::write(
        dir.join("callee.h"),
        "#ifndef CALLEE_H\n#define CALLEE_H\nint make_room(int n);\n#endif\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("callee.c"),
        "#include \"callee.h\"\nint make_room(int n) {\n    return n + 1;\n}\n",
    )
    .unwrap();
    // The call to make_room sits on line 3 (1-indexed) of caller.c.
    let caller_src = "#include \"callee.h\"\n\
int do_work(int x) {\n\
    int y = make_room(x);\n\
    return y;\n\
}\n";
    std::fs::write(dir.join("caller.c"), caller_src).unwrap();

    let graph = build_project_call_graph(&dir, Language::C, None, true)
        .expect("build project call graph");

    let edge = graph
        .edges()
        .find(|e| e.src_func == "do_work" && e.dst_func.ends_with("make_room"))
        .cloned()
        .unwrap_or_else(|| {
            panic!(
                "no do_work->make_room edge found; edges: {:?}",
                graph
                    .edges()
                    .map(|e| (e.src_func.clone(), e.dst_func.clone()))
                    .collect::<Vec<_>>()
            )
        });

    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(
        edge.call_line,
        Some(3),
        "cross-file edge do_work->make_room must carry the real call-site line (3), got {:?}",
        edge.call_line
    );
}
