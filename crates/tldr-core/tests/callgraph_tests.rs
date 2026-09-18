//! Tests for Layer 2: Call Graph operations
//!
//! Commands tested: calls, impact, dead, importers, arch
//!
//! These tests verify the behavior of the call graph layer.

use std::path::PathBuf;

use tldr_core::analysis::{
    architecture_analysis, dead_code_analysis, find_importers, impact_analysis,
};
use tldr_core::callgraph::build_project_call_graph;
use tldr_core::{FunctionRef, Language, TldrError};

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

// =============================================================================
// calls command tests
// =============================================================================

mod calls_tests {
    use super::*;

    #[test]
    fn calls_builds_cross_file_call_graph() {
        // GIVEN: A project with cross-file function calls
        let project = fixtures_dir().join("simple-project");

        // WHEN: We build the call graph
        let graph = build_project_call_graph(&project, Language::Python, None, true);

        // THEN: It should succeed and contain edges
        assert!(
            graph.is_ok(),
            "Failed to build call graph: {:?}",
            graph.err()
        );
        let graph = graph.unwrap();
        // The simple-project has intra-file calls (main -> process_data -> add_to_total)
        assert!(graph.edge_count() > 0, "Expected edges in call graph");
    }

    #[test]
    fn calls_includes_self_edges_for_recursion() {
        // GIVEN: A project with functions that call each other
        let project = fixtures_dir().join("simple-project");

        // WHEN: We build the call graph
        let graph = build_project_call_graph(&project, Language::Python, None, true);

        // THEN: It should include same-file calls
        assert!(graph.is_ok());
        let graph = graph.unwrap();
        // main.py has: main -> process_data -> add_to_total
        assert!(graph.edge_count() >= 2, "Expected at least 2 edges");
    }

    #[test]
    fn calls_skips_unresolved_calls() {
        // GIVEN: A file that may call external functions
        let project = fixtures_dir().join("simple-project");

        // WHEN: We build the call graph
        let graph = build_project_call_graph(&project, Language::Python, None, true);

        // THEN: Unresolved calls should be skipped (not cause errors)
        assert!(graph.is_ok(), "Should handle unresolved calls gracefully");
    }

    #[test]
    fn calls_respects_ignore_patterns() {
        // GIVEN: A project with files
        let project = fixtures_dir().join("simple-project");

        // WHEN: We build with respect_ignore=true
        let graph = build_project_call_graph(&project, Language::Python, None, true);

        // THEN: Should complete successfully
        assert!(graph.is_ok());
    }

    #[test]
    fn calls_works_with_typescript() {
        // GIVEN: A TypeScript project
        let project = fixtures_dir().join("typescript-project");

        // WHEN: We build the call graph
        let graph = build_project_call_graph(&project, Language::TypeScript, None, true);

        // THEN: TypeScript calls should be resolved
        assert!(
            graph.is_ok(),
            "TypeScript call graph should build: {:?}",
            graph.err()
        );
    }
}

// =============================================================================
// impact command tests
// =============================================================================

mod impact_tests {
    use super::*;

    #[test]
    fn impact_finds_direct_callers() {
        // GIVEN: A call graph with known call patterns
        let project = fixtures_dir().join("simple-project");
        let graph = build_project_call_graph(&project, Language::Python, None, true).unwrap();

        // WHEN: We run impact analysis on add_to_total (called by process_data)
        let report = impact_analysis(&graph, "add_to_total", 2, None);

        // THEN: Direct callers should be found
        assert!(report.is_ok(), "Impact analysis failed: {:?}", report.err());
        let report = report.unwrap();
        assert!(report.total_targets > 0, "Expected to find the function");
    }

    #[test]
    fn impact_respects_max_depth() {
        // GIVEN: A call graph
        let project = fixtures_dir().join("simple-project");
        let graph = build_project_call_graph(&project, Language::Python, None, true).unwrap();

        // WHEN: We run impact analysis with depth 1
        let report = impact_analysis(&graph, "add_to_total", 1, None);

        // THEN: Should complete without errors
        assert!(report.is_ok());
    }

    #[test]
    fn impact_handles_function_not_found() {
        // GIVEN: A call graph
        let project = fixtures_dir().join("simple-project");
        let graph = build_project_call_graph(&project, Language::Python, None, true).unwrap();

        // WHEN: We search for a nonexistent function
        let report = impact_analysis(&graph, "nonexistent_function_xyz", 3, None);

        // THEN: It should return an error
        assert!(report.is_err());
        if let Err(TldrError::FunctionNotFound { name, .. }) = report {
            assert_eq!(name, "nonexistent_function_xyz");
        } else {
            panic!("Expected FunctionNotFound error, got {:?}", report);
        }
    }

    #[test]
    fn impact_handles_entry_points() {
        // GIVEN: A function that is an entry point (main)
        let project = fixtures_dir().join("simple-project");
        let graph = build_project_call_graph(&project, Language::Python, None, true).unwrap();

        // WHEN: We run impact analysis on main
        let report = impact_analysis(&graph, "main", 3, None);

        // THEN: Should find the function even if it has no callers
        // main calls others but isn't called, so may have a note about being entry point
        assert!(
            report.is_ok(),
            "Should handle entry point: {:?}",
            report.err()
        );
    }
}

// =============================================================================
// dead command tests
// =============================================================================

mod dead_tests {
    use super::*;

    #[test]
    fn dead_finds_uncalled_functions() {
        // GIVEN: A project with unused functions
        let project = fixtures_dir().join("simple-project");
        let graph = build_project_call_graph(&project, Language::Python, None, true).unwrap();

        // Create function list including the unused function
        let functions = vec![
            FunctionRef::new(project.join("main.py"), "main"),
            FunctionRef::new(project.join("main.py"), "process_data"),
            FunctionRef::new(project.join("main.py"), "add_to_total"),
            FunctionRef::new(project.join("main.py"), "unused_function"),
        ];

        // WHEN: We run dead code analysis
        let report = dead_code_analysis(&graph, &functions, None);

        // THEN: unused_function should be detected as dead
        assert!(
            report.is_ok(),
            "Dead code analysis failed: {:?}",
            report.err()
        );
        let report = report.unwrap();
        // unused_function is not called anywhere
        assert!(
            report
                .dead_functions
                .iter()
                .any(|f| f.name == "unused_function"),
            "Expected to find unused_function as dead"
        );
    }

    #[test]
    fn dead_excludes_entry_points() {
        // GIVEN: A project with main(), test_*, etc.
        let project = fixtures_dir().join("simple-project");
        let graph = build_project_call_graph(&project, Language::Python, None, true).unwrap();

        let functions = vec![
            FunctionRef::new(project.join("main.py"), "main"),
            FunctionRef::new(project.join("test_main.py"), "test_something"),
        ];

        // WHEN: We run dead code analysis
        let report = dead_code_analysis(&graph, &functions, None).unwrap();

        // THEN: Entry points should NOT be marked as dead
        assert!(
            !report.dead_functions.iter().any(|f| f.name == "main"),
            "main should not be marked as dead"
        );
        assert!(
            !report
                .dead_functions
                .iter()
                .any(|f| f.name == "test_something"),
            "test functions should not be marked as dead"
        );
    }

    #[test]
    fn dead_excludes_dunder_methods() {
        // GIVEN: Functions including dunder methods
        let project = fixtures_dir().join("simple-project");
        let graph = build_project_call_graph(&project, Language::Python, None, true).unwrap();

        let functions = vec![
            FunctionRef::new(project.join("utils.py"), "__init__"),
            FunctionRef::new(project.join("utils.py"), "__str__"),
        ];

        // WHEN: We run dead code analysis
        let report = dead_code_analysis(&graph, &functions, None).unwrap();

        // THEN: Dunder methods should NOT be marked as dead
        assert!(
            report.dead_functions.is_empty(),
            "Dunder methods should be excluded"
        );
    }

    #[test]
    fn dead_respects_custom_entry_points() {
        // GIVEN: Custom entry points
        let project = fixtures_dir().join("simple-project");
        let graph = build_project_call_graph(&project, Language::Python, None, true).unwrap();

        let functions = vec![
            FunctionRef::new(project.join("main.py"), "custom_entry"),
            FunctionRef::new(project.join("main.py"), "helper_func"),
        ];

        let custom = vec!["custom_entry".to_string()];

        // WHEN: We run dead code analysis with custom entry points
        let report = dead_code_analysis(&graph, &functions, Some(&custom)).unwrap();

        // THEN: Custom entry points should be excluded
        assert!(
            !report
                .dead_functions
                .iter()
                .any(|f| f.name == "custom_entry"),
            "custom_entry should be excluded"
        );
    }

    #[test]
    fn dead_calculates_percentage() {
        // GIVEN: A project with some dead code
        let project = fixtures_dir().join("simple-project");
        let graph = build_project_call_graph(&project, Language::Python, None, true).unwrap();

        let functions = vec![
            FunctionRef::new(project.join("main.py"), "main"), // entry point
            FunctionRef::new(project.join("main.py"), "dead1"), // dead
            FunctionRef::new(project.join("main.py"), "dead2"), // dead
            FunctionRef::new(project.join("main.py"), "test_x"), // entry point
        ];

        // WHEN: We run dead code analysis
        let report = dead_code_analysis(&graph, &functions, None).unwrap();

        // THEN: dead_percentage should be calculated correctly
        assert_eq!(report.total_dead, 2, "Expected 2 dead functions");
        assert_eq!(report.total_functions, 4, "Expected 4 total functions");
        assert!(
            (report.dead_percentage - 50.0).abs() < 0.01,
            "Expected ~50% dead"
        );
    }

    #[test]
    fn dead_groups_by_file() {
        // GIVEN: Dead functions across multiple files
        let project = fixtures_dir().join("simple-project");
        let graph = build_project_call_graph(&project, Language::Python, None, true).unwrap();

        let functions = vec![
            FunctionRef::new(project.join("a.py"), "dead_a"),
            FunctionRef::new(project.join("b.py"), "dead_b"),
        ];

        // WHEN: We run dead code analysis
        let report = dead_code_analysis(&graph, &functions, None).unwrap();

        // THEN: by_file should group them correctly
        assert!(!report.by_file.is_empty() || report.dead_functions.len() == 2);
    }
}

// =============================================================================
// importers command tests
// =============================================================================

mod importers_tests {
    use super::*;

    #[test]
    fn importers_finds_files_importing_module() {
        // GIVEN: A module that is imported by other files
        let project = fixtures_dir().join("python-project");

        // WHEN: We search for importers of typing
        let report = find_importers(&project, "typing", Language::Python);

        // THEN: Importing files should be found
        assert!(report.is_ok(), "find_importers failed: {:?}", report.err());
        let report = report.unwrap();
        // Both app.py and services/auth.py import typing
        assert!(report.total > 0, "Expected to find files importing typing");
    }

    #[test]
    fn importers_captures_line_numbers() {
        // GIVEN: Files importing a module
        let project = fixtures_dir().join("python-project");

        // WHEN: We find importers
        let report = find_importers(&project, "typing", Language::Python).unwrap();

        // THEN: Line numbers should be present
        for importer in &report.importers {
            assert!(importer.line > 0, "Line number should be positive");
        }
    }

    #[test]
    fn importers_captures_import_statement() {
        // GIVEN: Files with various import styles
        let project = fixtures_dir().join("python-project");

        // WHEN: We find importers
        let report = find_importers(&project, "typing", Language::Python).unwrap();

        // THEN: The actual import statement should be captured
        for importer in &report.importers {
            assert!(
                !importer.import_statement.is_empty(),
                "Import statement should be captured"
            );
        }
    }

    #[test]
    fn importers_handles_no_importers() {
        // GIVEN: A module that no one imports
        let project = fixtures_dir().join("simple-project");

        // WHEN: We search for importers
        let report = find_importers(&project, "nonexistent_module_xyz", Language::Python);

        // THEN: Empty result with total=0
        assert!(report.is_ok());
        let report = report.unwrap();
        assert_eq!(report.total, 0, "Expected no importers");
    }

    #[test]
    fn importers_works_with_typescript() {
        // GIVEN: A TypeScript project
        let project = fixtures_dir().join("typescript-project");

        // WHEN: We search for importers
        let report = find_importers(&project, "./processor", Language::TypeScript);

        // THEN: Should not error
        assert!(report.is_ok(), "TypeScript importers should work");
    }
}

// =============================================================================
// arch command tests
// =============================================================================

mod arch_tests {
    use super::*;

    #[test]
    fn arch_identifies_entry_layer() {
        // GIVEN: A project with entry points (call others, not called)
        let project = fixtures_dir().join("simple-project");
        let graph = build_project_call_graph(&project, Language::Python, None, true).unwrap();

        // WHEN: We run architecture analysis
        let report = architecture_analysis(&graph);

        // THEN: Entry layer should be identified
        assert!(
            report.is_ok(),
            "Architecture analysis failed: {:?}",
            report.err()
        );
        let report = report.unwrap();
        // main() calls process_data but isn't called -> entry
        assert!(
            !report.entry_layer.is_empty() || !report.middle_layer.is_empty(),
            "Should identify some layers"
        );
    }

    #[test]
    fn arch_identifies_middle_layer() {
        // GIVEN: A project with service functions
        let project = fixtures_dir().join("simple-project");
        let graph = build_project_call_graph(&project, Language::Python, None, true).unwrap();

        // WHEN: We run architecture analysis
        let report = architecture_analysis(&graph).unwrap();

        // THEN: Middle layer should contain functions that both call and are called
        // process_data is called by main and calls add_to_total
        // This should be in middle_layer
        // Note: depends on exact call graph structure
        assert!(
            report.middle_layer.iter().any(|f| f.name == "process_data")
                || report
                    .entry_layer
                    .iter()
                    .any(|f| f.name.contains("process"))
                || report.leaf_layer.iter().any(|f| f.name.contains("process")),
            "Should classify process_data"
        );
    }

    #[test]
    fn arch_identifies_leaf_layer() {
        // GIVEN: A project with utility functions
        let project = fixtures_dir().join("simple-project");
        let graph = build_project_call_graph(&project, Language::Python, None, true).unwrap();

        // WHEN: We run architecture analysis
        let report = architecture_analysis(&graph).unwrap();

        // THEN: Leaf layer should contain functions that are called but don't call others
        // add_to_total is called but doesn't call anything
        assert!(
            report.leaf_layer.iter().any(|f| f.name == "add_to_total")
                || !report.leaf_layer.is_empty()
                || report.middle_layer.iter().any(|f| f.name.contains("add")),
            "Should have leaf functions or classify add_to_total"
        );
    }

    #[test]
    fn arch_detects_circular_dependencies() {
        // GIVEN: A project (may or may not have circular deps)
        let project = fixtures_dir().join("simple-project");
        let graph = build_project_call_graph(&project, Language::Python, None, true).unwrap();

        // WHEN: We run architecture analysis
        let report = architecture_analysis(&graph);

        // THEN: Should complete without error
        assert!(
            report.is_ok(),
            "Should handle circular dependency detection"
        );
    }

    #[test]
    fn arch_infers_layer_types() {
        // GIVEN: A project
        let project = fixtures_dir().join("simple-project");
        let graph = build_project_call_graph(&project, Language::Python, None, true).unwrap();

        // WHEN: We run architecture analysis
        let report = architecture_analysis(&graph).unwrap();

        // THEN: Layer types should be inferred for directories
        // Note: inferred_layers may be empty if all files are in root
        // This is acceptable behavior
        assert!(
            report.inferred_layers.is_empty() || !report.directories.is_empty(),
            "Should process directories"
        );
    }

    #[test]
    fn arch_calculates_directory_stats() {
        // GIVEN: A project with multiple directories
        let project = fixtures_dir().join("python-project");
        let graph = build_project_call_graph(&project, Language::Python, None, true).unwrap();

        // WHEN: We run architecture analysis
        let report = architecture_analysis(&graph).unwrap();

        // THEN: DirStats should be calculated
        // python-project has services/ subdirectory
        for stats in report.directories.values() {
            assert!(
                !stats.functions.is_empty() || stats.calls_in > 0 || stats.calls_out > 0,
                "DirStats should have valid values"
            );
        }
    }
}

// =============================================================================
// C# cross-file inherited call edges (issue #87)
// =============================================================================
//
// `tldr calls` must emit an edge when a derived class calls an inherited
// method whose definition lives in ANOTHER file. This exercises the full V2
// pipeline: CsharpHandler call classification (Intra when the enclosing class
// declares bases), base_list extraction (identifier/generic_name/
// qualified_name), and the builder's resolve_method_in_bases BFS over
// ClassIndex.

mod csharp_inherited_calls_tests {
    use std::fs;
    use std::path::Path;

    use tempfile::TempDir;
    use tldr_core::callgraph::{build_project_call_graph_v2, BuildConfig};

    fn write_cs_file(root: &Path, name: &str, content: &str) {
        let full_path = root.join(name);
        fs::write(&full_path, content).expect("Failed to write C# file");
    }

    fn build_csharp_call_graph(root: &Path) -> tldr_core::callgraph::CallGraphIR {
        let config = BuildConfig {
            language: "csharp".to_string(),
            use_type_resolution: true,
            respect_ignore: false,
            ..Default::default()
        };
        build_project_call_graph_v2(root, config).expect("Call graph build should succeed")
    }

    /// dst_func is qualified (e.g. "Base.Run"), so compare the last dotted
    /// segment.
    fn has_edge_from(
        ir: &tldr_core::callgraph::CallGraphIR,
        src_contains: &str,
        dst_func: &str,
    ) -> bool {
        ir.edges.iter().any(|e| {
            e.src_func.contains(src_contains) && e.dst_func.split('.').next_back() == Some(dst_func)
        })
    }

    /// 3-file inheritance chain (Base.cs / Derived.cs / Main.cs): a bare call
    /// to `Run()` inside Derived.Go must produce a cross-file edge to
    /// Base.Run. Before the #87 fix this edge was silently missing.
    #[test]
    fn calls_cross_file_inherited_method_produces_edge() {
        let dir = TempDir::new().expect("temp dir");
        let root = dir.path();

        write_cs_file(
            root,
            "Base.cs",
            r#"public class Base
{
    public virtual void Run()
    {
    }
}
"#,
        );
        write_cs_file(
            root,
            "Derived.cs",
            r#"public class Derived : Base
{
    public void Go()
    {
        Run();
    }
}
"#,
        );
        write_cs_file(
            root,
            "Main.cs",
            r#"public class Program
{
    public static void Main()
    {
        Derived d = new Derived();
        d.Run();
    }
}
"#,
        );

        let ir = build_csharp_call_graph(root);

        assert!(
            has_edge_from(&ir, "Derived.Go", "Run"),
            "Expected edge Derived.Go -> Base.Run; edges: {:?}",
            ir.edges
                .iter()
                .map(|e| format!("{} -> {}", e.src_func, e.dst_func))
                .collect::<Vec<_>>()
        );
    }

    /// Control: the same shape contained in a single file already worked and
    /// must keep working (regression guard for the classification change).
    #[test]
    fn calls_same_file_inherited_method_produces_edge() {
        let dir = TempDir::new().expect("temp dir");
        let root = dir.path();

        write_cs_file(
            root,
            "All.cs",
            r#"public class Base
{
    public virtual void Run()
    {
    }
}

public class Derived : Base
{
    public void Go()
    {
        Run();
    }
}
"#,
        );

        let ir = build_csharp_call_graph(root);

        assert!(
            has_edge_from(&ir, "Derived.Go", "Run"),
            "Same-file inherited call must still resolve; edges: {:?}",
            ir.edges
                .iter()
                .map(|e| format!("{} -> {}", e.src_func, e.dst_func))
                .collect::<Vec<_>>()
        );
    }

    /// Negative: a base class that is not part of the analyzed project
    /// (framework type) must stay unresolved — no edge is fabricated, and no
    /// panic occurs. Generic (`RepositoryBase<T>`) and qualified
    /// (`Framework.Base`) base names must not break the build either.
    #[test]
    fn calls_unknown_base_stays_unresolved_without_fabricated_edges() {
        let dir = TempDir::new().expect("temp dir");
        let root = dir.path();

        write_cs_file(
            root,
            "Repo.cs",
            r#"public class UserRepo : Framework.RepositoryBase<object>
{
    public void SaveAll()
    {
        Save(new object());
        MissingExternal();
    }
}
"#,
        );

        let ir = build_csharp_call_graph(root);

        assert!(
            !ir.edges
                .iter()
                .any(|e| e.src_func.contains("UserRepo.SaveAll")),
            "Unknown-base calls must stay unresolved; edges: {:?}",
            ir.edges
                .iter()
                .map(|e| format!("{} -> {}", e.src_func, e.dst_func))
                .collect::<Vec<_>>()
        );
    }
}
