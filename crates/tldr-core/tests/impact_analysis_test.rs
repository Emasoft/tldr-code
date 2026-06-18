//! Test for impact_analysis API
//!
//! This API is used by the `impact` and `change-impact` CLI commands
//!
//! impact_analysis finds all callers of a function via reverse call graph traversal.

use std::path::PathBuf;
use tldr_core::analysis::impact_analysis;
use tldr_core::error::TldrError;
use tldr_core::types::{CallEdge, ProjectCallGraph};

/// Helper function to create a test call graph with a simple chain:
/// main() -> process() -> helper() -> utils()
///          process() -> validate()
fn create_simple_call_graph() -> ProjectCallGraph {
    let mut graph = ProjectCallGraph::new();

    // main() calls process()
    graph.add_edge(CallEdge {
        src_file: PathBuf::from("main.py"),
        src_func: "main".to_string(),
        dst_file: PathBuf::from("app.py"),
        dst_func: "process".to_string(),
        call_line: None,
    });

    // process() calls helper()
    graph.add_edge(CallEdge {
        src_file: PathBuf::from("app.py"),
        src_func: "process".to_string(),
        dst_file: PathBuf::from("helpers.py"),
        dst_func: "helper".to_string(),
        call_line: None,
    });

    // helper() calls utils()
    graph.add_edge(CallEdge {
        src_file: PathBuf::from("helpers.py"),
        src_func: "helper".to_string(),
        dst_file: PathBuf::from("utils.py"),
        dst_func: "utils".to_string(),
        call_line: None,
    });

    // process() also calls validate()
    graph.add_edge(CallEdge {
        src_file: PathBuf::from("app.py"),
        src_func: "process".to_string(),
        dst_file: PathBuf::from("validators.py"),
        dst_func: "validate".to_string(),
        call_line: None,
    });

    graph
}

/// Helper function to create a test call graph with multiple callers
/// A() -> C()
/// B() -> C()
fn create_multi_caller_graph() -> ProjectCallGraph {
    let mut graph = ProjectCallGraph::new();

    // A() calls shared()
    graph.add_edge(CallEdge {
        src_file: PathBuf::from("a.py"),
        src_func: "func_a".to_string(),
        dst_file: PathBuf::from("shared.py"),
        dst_func: "shared".to_string(),
        call_line: None,
    });

    // B() also calls shared()
    graph.add_edge(CallEdge {
        src_file: PathBuf::from("b.py"),
        src_func: "func_b".to_string(),
        dst_file: PathBuf::from("shared.py"),
        dst_func: "shared".to_string(),
        call_line: None,
    });

    // shared() calls util()
    graph.add_edge(CallEdge {
        src_file: PathBuf::from("shared.py"),
        src_func: "shared".to_string(),
        dst_file: PathBuf::from("util.py"),
        dst_func: "util".to_string(),
        call_line: None,
    });

    graph
}

#[test]
fn test_impact_analysis_happy_path_simple_chain() {
    // Arrange: Create a simple call chain
    let graph = create_simple_call_graph();

    // Act: Analyze impact of changing utils()
    let result = impact_analysis(&graph, "utils", 3, None);

    // Assert: Should succeed
    assert!(
        result.is_ok(),
        "impact_analysis should succeed for existing function"
    );

    let report = result.unwrap();
    assert_eq!(
        report.total_targets, 1,
        "Should find exactly one target function"
    );

    let tree = report.targets.values().next().unwrap();
    assert_eq!(tree.function, "utils", "Target function name should match");
    assert_eq!(
        tree.caller_count, 1,
        "utils() should have 1 direct caller (helper)"
    );
    assert_eq!(tree.callers.len(), 1, "Should have 1 caller in tree");

    // Check the caller chain
    let helper = &tree.callers[0];
    assert_eq!(helper.function, "helper", "First caller should be helper");
    assert_eq!(
        helper.caller_count, 1,
        "helper() should have 1 caller (process)"
    );

    let process = &helper.callers[0];
    assert_eq!(
        process.function, "process",
        "Second caller should be process"
    );

    println!("PASS: Impact analysis correctly traces call chain: utils <- helper <- process");
}

#[test]
fn test_impact_analysis_multiple_callers() {
    // Arrange: Create a graph with multiple callers
    let graph = create_multi_caller_graph();

    // Act: Analyze impact of changing shared()
    let result = impact_analysis(&graph, "shared", 2, None);

    // Assert: Should succeed and find both callers
    assert!(result.is_ok(), "impact_analysis should succeed");

    let report = result.unwrap();
    let tree = report.targets.values().next().unwrap();

    assert_eq!(
        tree.caller_count, 2,
        "shared() should have 2 direct callers"
    );
    assert_eq!(tree.callers.len(), 2, "Should have 2 callers in tree");

    // Verify both callers are found
    let caller_names: Vec<&str> = tree.callers.iter().map(|c| c.function.as_str()).collect();
    assert!(
        caller_names.contains(&"func_a"),
        "Should find func_a as caller"
    );
    assert!(
        caller_names.contains(&"func_b"),
        "Should find func_b as caller"
    );

    println!(
        "PASS: Impact analysis correctly finds multiple callers: {:?}",
        caller_names
    );
}

#[test]
fn test_impact_analysis_respects_depth_limit() {
    // Arrange: Create a deep call chain
    let graph = create_simple_call_graph();

    // Act: Analyze with depth limit of 1
    let result = impact_analysis(&graph, "utils", 1, None);

    // Assert: Should only show direct callers, truncate the rest
    assert!(result.is_ok());
    let report = result.unwrap();
    let tree = report.targets.values().next().unwrap();

    // At depth 1, we should see helper() but it should be truncated
    assert_eq!(tree.callers.len(), 1, "Should have 1 caller at depth 1");

    let helper = &tree.callers[0];
    assert!(
        helper.truncated,
        "helper() should be marked as truncated at depth limit"
    );
    assert!(helper.note.is_some(), "Truncated node should have a note");

    println!("PASS: Depth limit correctly truncates the call tree");
}

#[test]
fn test_impact_analysis_entry_point_no_callers() {
    // Arrange: Create a graph
    let graph = create_simple_call_graph();

    // Act: Analyze impact of main() which is an entry point (no callers)
    let result = impact_analysis(&graph, "main", 3, None);

    // Assert: Should succeed with 0 callers
    assert!(
        result.is_ok(),
        "impact_analysis should succeed for entry point"
    );

    let report = result.unwrap();
    let tree = report.targets.values().next().unwrap();

    assert_eq!(tree.caller_count, 0, "Entry point should have 0 callers");
    assert!(
        tree.callers.is_empty(),
        "Entry point should have empty callers list"
    );
    assert!(
        tree.note.is_some(),
        "Entry point should have a note explaining no callers"
    );

    println!("PASS: Entry point correctly identified with 0 callers");
}

#[test]
fn test_impact_analysis_nonexistent_function() {
    // Arrange: Create a graph
    let graph = create_simple_call_graph();

    // Act: Analyze impact of a non-existent function
    let result = impact_analysis(&graph, "nonexistent_function", 3, None);

    // Assert: Should return FunctionNotFound error
    assert!(result.is_err(), "Should error for non-existent function");

    match result {
        Err(TldrError::FunctionNotFound {
            name,
            file,
            suggestions,
        }) => {
            assert_eq!(
                name, "nonexistent_function",
                "Error should contain function name"
            );
            assert!(
                file.is_none(),
                "File should be None when no filter was provided"
            );
            // May have suggestions for similar names
            println!("PASS: Correctly returns FunctionNotFound error for 'nonexistent_function'");
            println!("   Suggestions: {:?}", suggestions);
        }
        Err(other) => {
            panic!("Expected FunctionNotFound error, got: {:?}", other);
        }
        Ok(_) => {
            panic!("Expected error for non-existent function");
        }
    }
}

#[test]
fn test_impact_analysis_empty_graph() {
    // Arrange: Create an empty graph
    let graph = ProjectCallGraph::new();

    // Act: Analyze impact on empty graph
    let result = impact_analysis(&graph, "any_function", 3, None);

    // Assert: Should return FunctionNotFound error
    assert!(
        result.is_err(),
        "Should error when function not in empty graph"
    );

    match result {
        Err(TldrError::FunctionNotFound { name, .. }) => {
            assert_eq!(name, "any_function");
            println!("PASS: Correctly returns error for empty graph");
        }
        _ => panic!("Expected FunctionNotFound error for empty graph"),
    }
}

#[test]
fn test_impact_analysis_with_file_filter() {
    // Arrange: Create a graph with functions of same name in different files
    let mut graph = ProjectCallGraph::new();

    // process() in app.py calls helper()
    graph.add_edge(CallEdge {
        src_file: PathBuf::from("app.py"),
        src_func: "process".to_string(),
        dst_file: PathBuf::from("helpers.py"),
        dst_func: "helper".to_string(),
        call_line: None,
    });

    // process() in other.py also calls something
    graph.add_edge(CallEdge {
        src_file: PathBuf::from("other.py"),
        src_func: "process".to_string(),
        dst_file: PathBuf::from("util.py"),
        dst_func: "util".to_string(),
        call_line: None,
    });

    // Act: Filter by specific file
    let result = impact_analysis(&graph, "process", 3, Some(&PathBuf::from("app.py")));

    // Assert: Should find only the process() in app.py
    assert!(result.is_ok(), "Should succeed with file filter");

    let report = result.unwrap();
    assert_eq!(
        report.total_targets, 1,
        "Should find exactly one target with file filter"
    );

    let tree = report.targets.values().next().unwrap();
    assert!(
        tree.file.to_string_lossy().contains("app.py"),
        "Should match app.py"
    );

    println!("PASS: File filter correctly narrows down targets");
}

#[test]
fn test_impact_analysis_cyclic_call_detection() {
    // Arrange: Create a graph with a cycle: A -> B -> C -> A
    let mut graph = ProjectCallGraph::new();

    graph.add_edge(CallEdge {
        src_file: PathBuf::from("a.py"),
        src_func: "func_a".to_string(),
        dst_file: PathBuf::from("b.py"),
        dst_func: "func_b".to_string(),
        call_line: None,
    });

    graph.add_edge(CallEdge {
        src_file: PathBuf::from("b.py"),
        src_func: "func_b".to_string(),
        dst_file: PathBuf::from("c.py"),
        dst_func: "func_c".to_string(),
        call_line: None,
    });

    // Cycle back to A
    graph.add_edge(CallEdge {
        src_file: PathBuf::from("c.py"),
        src_func: "func_c".to_string(),
        dst_file: PathBuf::from("a.py"),
        dst_func: "func_a".to_string(),
        call_line: None,
    });

    // Act: Analyze impact starting from func_c
    let result = impact_analysis(&graph, "func_c", 5, None);

    // Assert: Should detect and handle cycle
    assert!(result.is_ok(), "Should handle cyclic calls");

    let report = result.unwrap();
    let tree = report.targets.values().next().unwrap();

    // Should find func_b as caller
    assert!(!tree.callers.is_empty(), "Should have callers");

    println!("PASS: Cycle detection works correctly in impact analysis");
}

// =============================================================================
// VAL-007: Multi-root workspace discovery + tsconfig path resolution
// =============================================================================

/// End-to-end acceptance test: in a pnpm-style monorepo, `impact` on an
/// exported function should either (a) find its cross-package caller via
/// resolved tsconfig path aliases, or (b) fall through to the AST-fallback
/// path and emit the new multi-root-aware note. The "misleading note with
/// zero callers" outcome that this milestone targets must NOT occur.
#[test]
fn test_impact_finds_callers_in_pnpm_monorepo() {
    use tldr_core::analysis::impact_analysis_with_ast_fallback;
    use tldr_core::callgraph::build_project_call_graph;
    use tldr_core::Language;

    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path();

    // Layout:
    //   root/pnpm-workspace.yaml
    //   root/apps/web/tsconfig.json    ({ paths: { "@/*": ["src/*"] } })
    //   root/apps/web/src/util.ts      (export function myUtil() { ... })
    //   root/apps/web/src/app.ts       (import { myUtil } from "@/util"; ...)
    std::fs::write(
        root.join("pnpm-workspace.yaml"),
        "packages:\n  - 'apps/*'\n",
    )
    .unwrap();

    let web = root.join("apps/web");
    let web_src = web.join("src");
    std::fs::create_dir_all(&web_src).unwrap();

    std::fs::write(
        web.join("tsconfig.json"),
        r#"{"compilerOptions":{"baseUrl":".","paths":{"@/*":["src/*"]}}}"#,
    )
    .unwrap();

    std::fs::write(
        web_src.join("util.ts"),
        "export function myUtil(): number { return 1; }\n",
    )
    .unwrap();

    std::fs::write(
        web_src.join("app.ts"),
        "import { myUtil } from \"@/util\";\n\
         export function main(): number { return myUtil(); }\n",
    )
    .unwrap();

    // Sanity check: discovery sees the web package.
    let ws = tldr_core::types::WorkspaceConfig::discover(root)
        .expect("pnpm workspace should be discovered");
    assert!(
        ws.roots.len() >= 2,
        "expected root + apps/web at minimum, got: {:?}",
        ws.roots,
    );

    // Build graph with the auto-discovered workspace config.
    let graph = build_project_call_graph(root, Language::TypeScript, None, true)
        .expect("callgraph build should succeed in pnpm monorepo fixture");

    let report =
        impact_analysis_with_ast_fallback(&graph, "myUtil", 3, None, root, Language::TypeScript)
            .expect("impact should succeed (either via edges or AST fallback)");

    assert_eq!(
        report.total_targets, 1,
        "should resolve to exactly one target"
    );
    let tree = report.targets.values().next().unwrap();

    // The ideal outcome (call edge resolution via per-package tsconfig)
    // OR the acceptable outcome (honest multi-root note) both satisfy the
    // VAL-007 contract: the tool must not silently lie about having
    // no callers.
    let note = tree.note.clone().unwrap_or_default();

    let has_callers = tree.caller_count >= 1;
    let has_honest_note = note.contains("workspace roots")
        || note.contains("path aliases")
        || note.contains("run from the workspace root");

    assert!(
        has_callers || has_honest_note,
        "expected callers OR multi-root aware note; got caller_count={}, note={:?}",
        tree.caller_count,
        note,
    );

    // The OLD misleading note is banned.
    assert!(
        !note.contains("no call edges in analyzed scope"),
        "VAL-007 regression: old misleading note resurfaced. note={:?}",
        note,
    );
}

// =============================================================================
// v031-issue-7: FuncIndex collision + impact.rs ends_with fuzzy match
// =============================================================================

/// FuncIndex simple_module alias overwrite — primary issue-7 reproducer.
///
/// FIXTURE
///   pkg1/foo.py defines `def process()` → module `pkg1.foo`, simple alias `foo`.
///   pkg2/foo.py defines `def process()` → module `pkg2.foo`, simple alias `foo`.
///
/// ROOT CAUSE
///   builder_v2 inserts each definition into func_index TWICE:
///     1) under the canonical full-module key (`pkg1.foo`, `process`)
///     2) under the simple_module alias key  (`foo`, `process`)
///   Step (2) is a HashMap::insert with no collision detection, so the
///   second writer silently overwrites the first under `("foo", "process")`.
///   The surviving entry depends on rayon's parallel processing order —
///   non-deterministic across builds.
///
/// POST-FIX INVARIANT (locked here)
///   builder_v2 must NOT silently overwrite the simple_module alias slot
///   when the existing entry points at a DIFFERENT file. Each definition
///   stays addressable under its canonical full-module key
///   (`pkg1.foo`, `process`) and (`pkg2.foo`, `process`); the simple alias
///   slot is no longer a single-entry race condition that hides one of
///   the two definitions.
///
/// VERIFICATION
///   After the build, `tldr impact process` (no file filter) must surface
///   BOTH defining files via either the call-graph edges or the AST
///   fallback path that impact_analysis_with_ast_fallback exposes. Today,
///   pre-fix, the simple_module overwrite collapses both edges to a single
///   dst_file. Post-fix, the canonical full-module entries remain
///   addressable and the resolver yields edges to BOTH files, so impact
///   analysis surfaces TWO distinct (dst_file, dst_func) targets.
#[test]
fn test_impact_distinguishes_same_name_in_different_modules() {
    use tldr_core::analysis::impact_analysis_with_ast_fallback;
    use tldr_core::callgraph::build_project_call_graph;
    use tldr_core::Language;

    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path();

    let pkg1 = root.join("pkg1");
    let pkg2 = root.join("pkg2");
    std::fs::create_dir_all(&pkg1).unwrap();
    std::fs::create_dir_all(&pkg2).unwrap();

    std::fs::write(pkg1.join("foo.py"), "def process():\n    return 1\n").unwrap();
    std::fs::write(pkg2.join("foo.py"), "def process():\n    return 2\n").unwrap();

    let graph = build_project_call_graph(root, Language::Python, None, true)
        .expect("callgraph build should succeed");

    // Even with no callers (impact_analysis_with_ast_fallback should kick
    // in via AST search), both pkg1/foo.py and pkg2/foo.py must be
    // surfaced as distinct targets — the FuncIndex collision must NOT
    // collapse them into one.
    let report =
        impact_analysis_with_ast_fallback(&graph, "process", 3, None, root, Language::Python)
            .expect("impact_analysis_with_ast_fallback should find process");

    let target_files: std::collections::HashSet<_> = report
        .targets
        .values()
        .map(|t| t.file.to_string_lossy().replace('\\', "/"))
        .collect();

    assert_eq!(
        report.total_targets, 2,
        "expected 2 distinct `process` targets (one per file); got {} — cross-module bleed via FuncIndex overwrite. target_files={:?}",
        report.total_targets,
        target_files,
    );

    assert!(
        target_files
            .iter()
            .any(|f| f.ends_with("pkg1/foo.py") || f.contains("/pkg1/foo.py")),
        "expected target file pkg1/foo.py; got targets: {:?}",
        target_files,
    );
    assert!(
        target_files
            .iter()
            .any(|f| f.ends_with("pkg2/foo.py") || f.contains("/pkg2/foo.py")),
        "expected target file pkg2/foo.py; got targets: {:?}",
        target_files,
    );
}

/// Locks the FuncIndex API contract: inserting two entries with DISTINCT
/// (module, name) keys preserves both lookups (both `pkg1.foo::process`
/// AND `pkg2.foo::process` resolvable). This is existing-good behavior we
/// guard against regression of the simple_module aliasing fix accidentally
/// disabling all aliasing.
#[test]
fn test_func_index_preserves_distinct_modules_with_same_simple_name() {
    use tldr_core::callgraph::{FuncEntry, FuncIndex};

    let mut idx = FuncIndex::new();

    let entry_a = FuncEntry::function(PathBuf::from("pkg1/foo.py"), 1, 2);
    let entry_b = FuncEntry::function(PathBuf::from("pkg2/foo.py"), 1, 2);

    idx.insert("pkg1.foo", "process", entry_a.clone());
    idx.insert("pkg2.foo", "process", entry_b.clone());

    let resolved_a = idx
        .get("pkg1.foo", "process")
        .expect("pkg1.foo::process must resolve");
    assert_eq!(
        resolved_a.file_path,
        PathBuf::from("pkg1/foo.py"),
        "pkg1.foo::process must resolve to pkg1/foo.py"
    );

    let resolved_b = idx
        .get("pkg2.foo", "process")
        .expect("pkg2.foo::process must resolve");
    assert_eq!(
        resolved_b.file_path,
        PathBuf::from("pkg2/foo.py"),
        "pkg2.foo::process must resolve to pkg2/foo.py — overwrite regression"
    );
}

/// Guards the impact.rs:54 `ends_with(".target")` fuzzy bug under the
/// target_file filter. Two functions, `helper` (in `helpers.py`) and
/// `data_helper` (in `data_helpers.py`). Filtering by target_file
/// `"helpers.py"` must NOT match `data_helpers.py` (which fuzzy-ends-with
/// `helpers.py`) — the path filter must respect segment boundaries.
#[test]
fn test_impact_file_filter_respects_segment_boundary() {
    let mut graph = ProjectCallGraph::new();

    graph.add_edge(CallEdge {
        src_file: PathBuf::from("app.py"),
        src_func: "main".to_string(),
        dst_file: PathBuf::from("helpers.py"),
        dst_func: "helper".to_string(),
        call_line: None,
    });

    graph.add_edge(CallEdge {
        src_file: PathBuf::from("data_app.py"),
        src_func: "main_d".to_string(),
        dst_file: PathBuf::from("data_helpers.py"),
        dst_func: "helper".to_string(),
        call_line: None,
    });

    let report = impact_analysis(&graph, "helper", 3, Some(&PathBuf::from("helpers.py")))
        .expect("filter by helpers.py should find helper in helpers.py");

    assert_eq!(
        report.total_targets, 1,
        "filter `helpers.py` must resolve to exactly 1 target (helpers.py only — data_helpers.py is a segment-boundary false positive)"
    );

    let tree = report.targets.values().next().unwrap();
    let file_str = tree.file.to_string_lossy().replace('\\', "/");
    assert_eq!(
        file_str, "helpers.py",
        "filter must select helpers.py exactly, not data_helpers.py; got {}",
        file_str,
    );
}
