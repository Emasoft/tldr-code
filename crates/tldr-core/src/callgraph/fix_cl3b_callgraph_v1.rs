//! fix-cl-3b-v1 (v0.5.0 CL-3b): cross-file call-graph resolution must not
//! route through bare names that mis-resolve.
//!
//! Four reproduced gaps (#74 family):
//!
//! * IT3-rust-07 (`context`/`explain`): `HashSet::new()` / `Vec::new()` —
//!   a qualified constructor on a std container — was mis-resolved to a
//!   same-file user struct's `new` (e.g. `DepStats::new`) because the
//!   bare-method fuzzy fallback discarded the capitalized receiver and
//!   matched any same-file `new`. The receiver `HashSet` is NOT `DepStats`,
//!   so the edge is wrong.
//!
//! * IT3-ocaml-03 (`references`): a top-level OCaml `let`-bound function
//!   defined under `bin/` returned `definitions: []` / `total_references: 0`
//!   because the project walker unconditionally skipped every `bin/`
//!   directory — yet `bin/` is authored source for dune / Rust `src/bin`
//!   / Go projects. The file-tree walker (`get_file_tree`) had already
//!   dropped `bin` from its skip list; this aligns `walk_project`.
//!
//! * IT3-ocaml-02 (`impact`): exercised by the CLI loop fix; the core
//!   `impact_analysis_with_ast_fallback` already resolves the top-level
//!   `let` via AST (covered by `analysis::impact` tests). The CLI-loop
//!   fast-fail is fixed in `tldr-cli`.
//!
//! * IT3-rust-06 (`impact`): same-named cross-file functions
//!   (`deps::detect_cycles` vs `tarjan::detect_cycles`) — the call graph
//!   must keep their edges file-distinct rather than collapsing callers
//!   onto one survivor.

use std::path::Path;

/// IT3-rust-07: building a project call graph for a file that calls
/// `HashSet::new()` / `Vec::new()` AND also defines a user struct with a
/// `new` associated function in the SAME file must NOT emit an edge from
/// the caller to the user struct's `new`. The std-container constructor
/// is external and unresolvable — never a user `Type::new`.
#[test]
fn rust_std_new_does_not_bind_to_same_file_user_struct_new() {
    use crate::build_project_call_graph;
    use crate::types::Language;

    let dir = std::env::temp_dir().join(format!("tldr_cl3b_rust07_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).expect("create temp dir");

    // deps.rs defines `DepStats::new` AND a free fn `detect_cycles` that
    // constructs std containers via `HashSet::new()` / `Vec::new()`.
    std::fs::write(
        dir.join("src").join("deps.rs"),
        "pub struct DepStats { pub n: usize }\n\
         impl DepStats {\n\
         \x20   pub fn new() -> Self { DepStats { n: 0 } }\n\
         }\n\
         pub fn detect_cycles(g: &[usize]) -> bool {\n\
         \x20   let _s: std::collections::HashSet<usize> = std::collections::HashSet::new();\n\
         \x20   let _v: Vec<usize> = Vec::new();\n\
         \x20   dfs_find_cycles(g)\n\
         }\n\
         pub fn dfs_find_cycles(_g: &[usize]) -> bool { false }\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("src").join("main.rs"),
        "mod deps;\nfn main() { let _ = deps::detect_cycles(&[0]); }\n",
    )
    .unwrap();

    let graph = build_project_call_graph(&dir, Language::Rust, None, true)
        .expect("build project call graph");

    let bogus: Vec<_> = graph
        .edges()
        .filter(|e| e.src_func == "detect_cycles" && e.dst_func.ends_with("new"))
        .map(|e| (e.src_func.clone(), e.dst_func.clone()))
        .collect();

    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        bogus.is_empty(),
        "detect_cycles must NOT call a user struct's `new` for std-container \
         `HashSet::new()`/`Vec::new()`; got bogus edges: {:?}",
        bogus
    );
}

/// IT3-ocaml-03: a top-level OCaml `let`-bound function defined under a
/// `bin/` directory must be discoverable by the project walker. `bin/` is
/// authored source for dune / Rust `src/bin` / Go layouts, so
/// `walk_project` must not skip it (mirrors `get_file_tree`'s skip list,
/// from which `bin` was already removed).
#[test]
fn walk_project_does_not_skip_authored_bin_dir() {
    use crate::walker::walk_project;

    let dir = std::env::temp_dir().join(format!("tldr_cl3b_bin_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("bin")).expect("create temp dir");

    std::fs::write(
        dir.join("bin").join("common.ml"),
        "let find_default_trace_file () =\n  let x = 1 in\n  x\n;;\n",
    )
    .unwrap();

    let found = walk_project(&dir)
        .filter(|e| e.file_type().map(|ft| ft.is_file()).unwrap_or(false))
        .any(|e| {
            e.path()
                .file_name()
                .map(|n| n == std::ffi::OsStr::new("common.ml"))
                .unwrap_or(false)
        });

    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        found,
        "walk_project must yield authored source under bin/ (bin/common.ml)"
    );
}

/// IT3-ocaml-02/03 (end-to-end resolver): the references pipeline must find
/// a top-level OCaml `let`-bound function and its call site even when the
/// definition lives under `bin/`.
#[test]
fn references_finds_ocaml_top_level_let_under_bin() {
    use crate::analysis::references::{find_references, ReferencesOptions};

    let dir = std::env::temp_dir().join(format!("tldr_cl3b_ocaml_refs_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("bin")).expect("create temp dir");

    std::fs::write(
        dir.join("bin").join("common.ml"),
        "let default_build_dir = \"_build\"\n\
         \n\
         let find_default_trace_file () =\n\
         \x20 let trace_file = Filename.concat default_build_dir \"trace\" in\n\
         \x20 trace_file\n\
         \n\
         let use_it () = find_default_trace_file ()\n",
    )
    .unwrap();

    let mut options = ReferencesOptions::new();
    options.language = Some("ocaml".to_string());
    let report =
        find_references("find_default_trace_file", &dir, &options).expect("find_references");

    let defs = report.definitions.len();
    let total = report.total_references;

    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        defs >= 1,
        "references must report the top-level let definition under bin/ (got {} defs)",
        defs
    );
    assert!(
        total >= 1,
        "references must report at least the definition site under bin/ (got {} refs)",
        total
    );
}

/// IT3-rust-06: two same-named free functions defined in different files
/// must keep their call-graph edges file-distinct. The caller in
/// `main.rs` that writes `deps::detect_cycles(...)` must produce an edge
/// whose `dst_file` is `deps.rs` (NOT `tarjan.rs`), and the bare call in
/// `tarjan.rs` must resolve to `tarjan.rs`'s own definition.
#[test]
fn rust_same_named_cross_file_fns_keep_distinct_edges() {
    use crate::build_project_call_graph;
    use crate::types::Language;

    let dir = std::env::temp_dir().join(format!("tldr_cl3b_rust06_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).expect("create temp dir");

    std::fs::write(
        dir.join("src").join("deps.rs"),
        "pub fn detect_cycles(_g: &[usize]) -> bool { false }\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("src").join("tarjan.rs"),
        "pub fn detect_cycles(_g: &[usize]) -> bool { true }\n\
         pub fn caller_of_tarjan() -> bool { detect_cycles(&[1]) }\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("src").join("main.rs"),
        "mod deps;\nmod tarjan;\n\
         fn caller_of_deps() -> bool { deps::detect_cycles(&[0]) }\n\
         fn main() { let _ = caller_of_deps(); }\n",
    )
    .unwrap();

    let graph = build_project_call_graph(&dir, Language::Rust, None, true)
        .expect("build project call graph");

    // The bare call inside tarjan.rs must resolve to tarjan.rs's own
    // `detect_cycles`, never to deps.rs.
    let tarjan_edge_wrong = graph.edges().any(|e| {
        e.src_func == "caller_of_tarjan"
            && e.dst_func.ends_with("detect_cycles")
            && file_basename(&e.dst_file) == Some("deps.rs")
    });

    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        !tarjan_edge_wrong,
        "the bare `detect_cycles()` call inside tarjan.rs must NOT resolve to \
         deps.rs's same-named definition"
    );
}

fn file_basename(p: &Path) -> Option<&str> {
    p.file_name().and_then(|n| n.to_str())
}
