//! Tests for Layer 5: PDG (Program Dependence Graph) operations
//!
//! Commands tested: pdg, slice
//!
//! These tests verify PDG construction and program slicing functionality.

use std::path::PathBuf;

use tldr_core::pdg::{get_pdg_context, get_slice};
use tldr_core::{DependenceType, Language, SliceDirection};

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

// =============================================================================
// PDG Construction Tests
// =============================================================================

mod pdg_construction_tests {
    use super::*;

    #[test]
    fn pdg_creates_nodes_from_cfg_blocks() {
        // GIVEN: A simple function
        let source = r#"
def foo():
    x = 1
    return x
"#;

        // WHEN: We extract the PDG
        let pdg = get_pdg_context(source, "foo", Language::Python).unwrap();

        // THEN: PDG should have nodes corresponding to CFG blocks
        assert!(!pdg.nodes.is_empty(), "PDG should have nodes");
        // Should have at least entry block
        assert!(
            pdg.nodes.iter().any(|n| n.node_type == "entry"),
            "Should have entry node"
        );
    }

    #[test]
    fn pdg_creates_control_dependency_edges() {
        // GIVEN: A function with control flow
        let source = r#"
def foo(cond):
    if cond:
        x = 1
    else:
        x = 2
    return x
"#;

        // WHEN: We extract the PDG
        let pdg = get_pdg_context(source, "foo", Language::Python).unwrap();

        // THEN: Should have control dependency edges
        let control_edges: Vec<_> = pdg
            .edges
            .iter()
            .filter(|e| e.dep_type == DependenceType::Control)
            .collect();
        assert!(
            !control_edges.is_empty(),
            "PDG should have control dependency edges"
        );
    }

    #[test]
    fn pdg_creates_data_dependency_edges() {
        // GIVEN: A function with data flow
        let source = r#"
def foo():
    x = 1
    y = x + 2
    return y
"#;

        // WHEN: We extract the PDG
        let pdg = get_pdg_context(source, "foo", Language::Python).unwrap();

        // THEN: Should have data dependency edges
        let data_edges: Vec<_> = pdg
            .edges
            .iter()
            .filter(|e| e.dep_type == DependenceType::Data)
            .collect();
        assert!(
            !data_edges.is_empty(),
            "PDG should have data dependency edges"
        );
    }

    #[test]
    fn pdg_preserves_cfg_structure() {
        // GIVEN: A function
        let source = r#"
def foo():
    x = 1
    return x
"#;

        // WHEN: We extract the PDG
        let pdg = get_pdg_context(source, "foo", Language::Python).unwrap();

        // THEN: PDG should contain the original CFG
        assert!(!pdg.cfg.blocks.is_empty(), "PDG should contain CFG blocks");
        assert_eq!(pdg.cfg.function, "foo", "CFG function name should match");
    }

    #[test]
    fn pdg_preserves_dfg_structure() {
        // GIVEN: A function
        let source = r#"
def foo():
    x = 1
    return x
"#;

        // WHEN: We extract the PDG
        let pdg = get_pdg_context(source, "foo", Language::Python).unwrap();

        // THEN: PDG should contain the original DFG
        assert!(!pdg.dfg.refs.is_empty(), "PDG should contain DFG refs");
        assert_eq!(pdg.dfg.function, "foo", "DFG function name should match");
    }

    #[test]
    fn pdg_nodes_track_definitions() {
        // GIVEN: A function with variable definitions
        let source = r#"
def foo():
    x = 1
    y = 2
    return x + y
"#;

        // WHEN: We extract the PDG
        let pdg = get_pdg_context(source, "foo", Language::Python).unwrap();

        // THEN: Nodes should track which variables are defined
        let total_defs: usize = pdg.nodes.iter().map(|n| n.definitions.len()).sum();
        assert!(total_defs > 0, "PDG nodes should track definitions");
    }

    #[test]
    fn pdg_nodes_track_uses() {
        // GIVEN: A function with variable uses
        let source = r#"
def foo():
    x = 1
    y = x + 2
    return y
"#;

        // WHEN: We extract the PDG
        let pdg = get_pdg_context(source, "foo", Language::Python).unwrap();

        // THEN: Nodes should track which variables are used
        let total_uses: usize = pdg.nodes.iter().map(|n| n.uses.len()).sum();
        assert!(total_uses > 0, "PDG nodes should track uses");
    }

    #[test]
    fn pdg_handles_function_not_found() {
        // GIVEN: A source without the target function
        let source = "def foo(): pass";

        // WHEN: We try to get PDG for nonexistent function
        let result = get_pdg_context(source, "nonexistent", Language::Python);

        // THEN: Should return error
        assert!(
            result.is_err(),
            "Should return error for nonexistent function"
        );
    }

    #[test]
    fn pdg_handles_nested_if() {
        // GIVEN: A function with nested conditionals
        let source = r#"
def nested(a, b):
    if a:
        if b:
            x = 1
        else:
            x = 2
    else:
        x = 3
    return x
"#;

        // WHEN: We extract the PDG
        let pdg = get_pdg_context(source, "nested", Language::Python).unwrap();

        // THEN: Should have multiple control dependencies
        let control_edges: Vec<_> = pdg
            .edges
            .iter()
            .filter(|e| e.dep_type == DependenceType::Control)
            .collect();
        assert!(
            control_edges.len() >= 2,
            "Nested ifs should create multiple control edges"
        );
    }

    #[test]
    fn pdg_handles_loops() {
        // GIVEN: A function with a loop
        let source = r#"
def loop_func():
    total = 0
    for i in range(10):
        total += i
    return total
"#;

        // WHEN: We extract the PDG
        let pdg = get_pdg_context(source, "loop_func", Language::Python).unwrap();

        // THEN: Should have control dependencies from loop header
        assert!(!pdg.nodes.is_empty(), "PDG should have nodes for loops");
    }

    #[test]
    fn pdg_edge_labels_for_data_deps() {
        // GIVEN: A function with data flow
        let source = r#"
def foo():
    x = 1
    y = x
    return y
"#;

        // WHEN: We extract the PDG
        let pdg = get_pdg_context(source, "foo", Language::Python).unwrap();

        // THEN: Data dependency edges should have variable labels
        let data_edges: Vec<_> = pdg
            .edges
            .iter()
            .filter(|e| e.dep_type == DependenceType::Data)
            .collect();

        for edge in &data_edges {
            assert!(
                !edge.label.is_empty(),
                "Data dependency edges should have labels"
            );
        }
    }

    #[test]
    fn pdg_node_types_are_accurate() {
        // GIVEN: A function with various constructs
        let source = r#"
def mixed(cond):
    if cond:
        return 1
    return 0
"#;

        // WHEN: We extract the PDG
        let pdg = get_pdg_context(source, "mixed", Language::Python).unwrap();

        // THEN: Should have predicate nodes for branches
        let predicates: Vec<_> = pdg
            .nodes
            .iter()
            .filter(|n| n.node_type == "predicate")
            .collect();
        assert!(
            !predicates.is_empty(),
            "Should have predicate nodes for if conditions"
        );
    }

    #[test]
    fn pdg_handles_empty_function() {
        // GIVEN: An empty function
        let source = r#"
def empty():
    pass
"#;

        // WHEN: We extract the PDG
        let pdg = get_pdg_context(source, "empty", Language::Python).unwrap();

        // THEN: Should have at least entry node
        assert!(
            !pdg.nodes.is_empty(),
            "Empty function should still have PDG nodes"
        );
    }

    #[test]
    fn pdg_handles_multiple_returns() {
        // GIVEN: A function with multiple returns
        let source = r#"
def multi(x):
    if x > 0:
        return 1
    elif x < 0:
        return -1
    return 0
"#;

        // WHEN: We extract the PDG
        let pdg = get_pdg_context(source, "multi", Language::Python).unwrap();

        // THEN: PDG should be constructed successfully
        assert!(!pdg.nodes.is_empty(), "Multiple returns should be handled");
    }

    #[test]
    fn pdg_integrates_cfg_and_dfg() {
        // GIVEN: A complex function
        let source = r#"
def complex(a, b):
    x = a + 1
    if x > 0:
        y = b * 2
    else:
        y = b / 2
    return x + y
"#;

        // WHEN: We extract the PDG
        let pdg = get_pdg_context(source, "complex", Language::Python).unwrap();

        // THEN: Both control and data edges should be present
        let control_count = pdg
            .edges
            .iter()
            .filter(|e| e.dep_type == DependenceType::Control)
            .count();
        let data_count = pdg
            .edges
            .iter()
            .filter(|e| e.dep_type == DependenceType::Data)
            .count();

        assert!(control_count > 0, "Should have control dependencies");
        assert!(data_count > 0, "Should have data dependencies");
    }

    #[test]
    fn pdg_from_file_path() {
        // GIVEN: A file path
        let file = fixtures_dir().join("simple-project/main.py");

        // WHEN: We extract PDG from file
        let pdg = get_pdg_context(file.to_str().unwrap(), "process_data", Language::Python);

        // THEN: Should succeed
        assert!(pdg.is_ok(), "PDG extraction from file should work");
    }
}

// =============================================================================
// Program Slicing Tests
// =============================================================================

mod slicing_tests {
    use super::*;

    #[test]
    fn slice_backward_basic() {
        // GIVEN: A function with clear data dependencies
        let source = r#"
def foo():
    x = 1
    y = x + 2
    return y
"#;

        // WHEN: We compute backward slice from return
        let slice = get_slice(
            source,
            "foo",
            5,
            SliceDirection::Backward,
            None,
            Language::Python,
        )
        .unwrap();

        // THEN: Should include lines that affect the return
        assert!(!slice.is_empty(), "Backward slice should not be empty");
    }

    #[test]
    fn slice_forward_basic() {
        // GIVEN: A function with data flow
        let source = r#"
def foo():
    x = 1
    y = x + 2
    z = y * 3
    return z
"#;

        // WHEN: We compute forward slice from x = 1
        let slice = get_slice(
            source,
            "foo",
            3,
            SliceDirection::Forward,
            None,
            Language::Python,
        )
        .unwrap();

        // THEN: Should include lines affected by x = 1
        assert!(
            slice.contains(&3),
            "Forward slice should include starting line"
        );
    }

    #[test]
    fn slice_with_variable_filter() {
        // GIVEN: A function with multiple variables
        let source = r#"
def foo():
    x = 1
    y = 2
    z = x + y
    return z
"#;

        // WHEN: We slice backward filtering for only 'x'
        let slice = get_slice(
            source,
            "foo",
            5,
            SliceDirection::Backward,
            Some("x"),
            Language::Python,
        )
        .unwrap();

        // THEN: Should only include lines related to x
        assert!(!slice.is_empty(), "Filtered slice should not be empty");
    }

    #[test]
    fn slice_line_not_in_function() {
        // GIVEN: A line number outside the function
        let source = "def foo(): pass";

        // WHEN: We try to slice from that line
        let slice = get_slice(
            source,
            "foo",
            999,
            SliceDirection::Backward,
            None,
            Language::Python,
        )
        .unwrap();

        // THEN: Should return empty set
        assert!(
            slice.is_empty(),
            "Slice for line outside function should be empty"
        );
    }

    #[test]
    fn slice_backward_includes_control_deps() {
        // GIVEN: A function with control-dependent statements
        let source = r#"
def foo(cond):
    if cond:
        x = 1
    else:
        x = 2
    return x
"#;

        // WHEN: We compute backward slice from return
        let slice = get_slice(
            source,
            "foo",
            7,
            SliceDirection::Backward,
            None,
            Language::Python,
        )
        .unwrap();

        // THEN: Should include control dependencies
        assert!(
            !slice.is_empty(),
            "Backward slice should include control dependencies"
        );
    }

    #[test]
    fn slice_forward_includes_dependents() {
        // GIVEN: A function where one variable affects many
        let source = r#"
def foo():
    x = 1
    a = x + 1
    b = x + 2
    c = a + b
    return c
"#;

        // WHEN: We compute forward slice from x = 1
        let slice = get_slice(
            source,
            "foo",
            3,
            SliceDirection::Forward,
            None,
            Language::Python,
        )
        .unwrap();

        // THEN: Should include all lines affected by x
        assert!(
            slice.len() >= 2,
            "Forward slice should include dependent lines"
        );
    }

    #[test]
    fn slice_returns_valid_line_numbers() {
        // GIVEN: A function
        let source = r#"
def foo():
    x = 1
    return x
"#;

        // WHEN: We compute a slice
        let slice = get_slice(
            source,
            "foo",
            4,
            SliceDirection::Backward,
            None,
            Language::Python,
        )
        .unwrap();

        // THEN: All line numbers should be positive
        for &line in &slice {
            assert!(line > 0, "Line numbers should be positive");
        }
    }

    #[test]
    fn slice_empty_function() {
        // GIVEN: An empty function
        let source = r#"
def empty():
    pass
"#;

        // WHEN: We try to slice from a line
        let slice = get_slice(
            source,
            "empty",
            3,
            SliceDirection::Backward,
            None,
            Language::Python,
        )
        .unwrap();

        // why: the old test only unwrapped and left a comment saying the
        // result "depends on implementation" — a regression that returned
        // nonsense line numbers (out of range, or a huge slice for a 3-line
        // body) would never fail this test.
        //
        // why the bound is `def` + `pass` and not the `pass` line alone.
        // Printed PDG for this exact source (two nodes, zero edges):
        //     node id=0 lines=(2, 3) type="entry"
        //     node id=1 lines=(3, 3) type="statement"
        // `find_nodes_for_line` selects EVERY node whose range contains the
        // line, so line 3 selects both — the entry node matches because its
        // range (2,3) spans it. `nodes_to_lines` then emits each selected
        // node's full range, and the entry node contributes line 2. So the
        // def line arrives through the entry node's span, not through any
        // dependency: "at most the line itself" asserts a precision this
        // slicer does not have.
        //
        // Two things that look like the reason and are not. There is no
        // control edge: extractor.rs emits `DependenceType::Control` only
        // from a `Branch` or `LoopHeader` source, and a function header is
        // neither — this graph has no edges at all. And the two lines are
        // NOT one block; they are two overlapping nodes, which the printed
        // ranges above settle.
        //
        // The entry node's span is also a real, PRE-EXISTING precision bug,
        // not just a curiosity: for `def wide(a)` with four straight-line
        // statements the entry node spans (2,5), so a backward slice from
        // `return c` returns [2,3,4,5,6] and includes an unrelated `d = 99`.
        // Tracked in TRDD-3TCJKGWM. This test's (2..=3) is safe regardless,
        // because at three lines the entry span and the function coincide.
        assert!(
            slice.contains(&3),
            "the slice must contain the line sliced from: {slice:?}"
        );
        for &l in &slice {
            assert!(
                (2..=3).contains(&l),
                "slice line {l} is outside the `def`/`pass` body of this \
                 3-line function: {slice:?}"
            );
        }
    }

    #[test]
    fn slice_handles_both_directions() {
        // GIVEN: A function
        let source = r#"
def foo():
    x = 1
    y = x
    return y
"#;

        // WHEN: We slice in both directions
        let backward = get_slice(
            source,
            "foo",
            4,
            SliceDirection::Backward,
            None,
            Language::Python,
        );
        let forward = get_slice(
            source,
            "foo",
            3,
            SliceDirection::Forward,
            None,
            Language::Python,
        );

        // THEN: Both should succeed
        assert!(backward.is_ok(), "Backward slice should work");
        assert!(forward.is_ok(), "Forward slice should work");
    }

    #[test]
    fn slice_with_complex_control_flow() {
        // GIVEN: A function with complex control flow
        let source = r#"
def complex(n):
    total = 0
    for i in range(n):
        if i % 2 == 0:
            total += i
    return total
"#;

        // WHEN: We compute backward slice from return
        let slice = get_slice(
            source,
            "complex",
            7,
            SliceDirection::Backward,
            None,
            Language::Python,
        )
        .unwrap();

        // THEN: Should capture relevant lines
        assert!(
            !slice.is_empty(),
            "Slice should work with complex control flow"
        );
    }

    #[test]
    fn slice_respects_variable_filter_for_data_deps() {
        // GIVEN: A function with independent data flows
        let source = r#"
def foo():
    x = 1
    y = 2
    z = x + y
    return z
"#;

        // WHEN: We slice for only x
        let x_slice = get_slice(
            source,
            "foo",
            5,
            SliceDirection::Backward,
            Some("x"),
            Language::Python,
        )
        .unwrap();

        // WHEN: We slice for only y
        let y_slice = get_slice(
            source,
            "foo",
            5,
            SliceDirection::Backward,
            Some("y"),
            Language::Python,
        )
        .unwrap();

        // THEN: Slices should differ
        // Both should be non-empty but may overlap at the return line
        assert!(!x_slice.is_empty(), "X slice should not be empty");
        assert!(!y_slice.is_empty(), "Y slice should not be empty");
    }

    #[test]
    fn slice_from_file_path() {
        // GIVEN: A file path
        let file = fixtures_dir().join("simple-project/main.py");

        // WHEN: We compute slice from file
        let slice = get_slice(
            file.to_str().unwrap(),
            "process_data",
            10,
            SliceDirection::Backward,
            None,
            Language::Python,
        );

        // THEN: Should succeed
        assert!(slice.is_ok(), "Slicing from file should work");
    }

    #[test]
    fn slice_function_not_found() {
        // GIVEN: A file
        let file = fixtures_dir().join("simple-project/main.py");

        // WHEN: We try to slice nonexistent function
        let result = get_slice(
            file.to_str().unwrap(),
            "nonexistent",
            1,
            SliceDirection::Backward,
            None,
            Language::Python,
        );

        // THEN: Should return error
        assert!(
            result.is_err(),
            "Should return error for nonexistent function"
        );
    }

    #[test]
    fn slice_result_is_deterministic() {
        // GIVEN: A function
        let source = r#"
def foo():
    x = 1
    y = x + 2
    return y
"#;

        // WHEN: We compute the same slice multiple times
        let slice1 = get_slice(
            source,
            "foo",
            5,
            SliceDirection::Backward,
            None,
            Language::Python,
        )
        .unwrap();
        let slice2 = get_slice(
            source,
            "foo",
            5,
            SliceDirection::Backward,
            None,
            Language::Python,
        )
        .unwrap();

        // THEN: Results should be identical
        assert_eq!(slice1, slice2, "Slice results should be deterministic");
    }

    #[test]
    fn slice_excludes_unrelated_statement_in_straight_line_code() {
        // GIVEN: a branch-free function where one statement feeds nothing.
        // `c` <- `b` <- `a`; `d = 99` on line 5 is dead as far as `return c`
        // is concerned.
        let source = "\ndef wide(a):\n    b = a + 1\n    c = b + 2\n    d = 99\n    return c\n";

        // WHEN: we slice backward from `return c`
        let slice = get_slice(
            source,
            "wide",
            6,
            SliceDirection::Backward,
            None,
            Language::Python,
        )
        .unwrap();

        // THEN: line 5 is absent, and the dependency chain is present.
        //
        // why this is asserted as an exact set (TRDD-3TCJKGWM): the whole
        // defect was that a backward slice over branch-free code returned
        // [2,3,4,5,6] — the entire body — because one PDG node covered the
        // whole basic block. A `!contains(&5)` assertion alone would pass
        // again the moment the graph went coarse in some other way, so the
        // set is pinned: `c` (4) <- `b` (3) <- `a`, defined on the header
        // line 2, plus the criterion line 6.
        let mut lines: Vec<u32> = slice.into_iter().collect();
        lines.sort_unstable();
        assert_eq!(
            lines,
            vec![2, 3, 4, 6],
            "backward slice from `return c` must exclude the unrelated `d = 99` on line 5"
        );
    }

    /// Sort a slice into a pinned, comparable line vector.
    fn sorted(slice: std::collections::HashSet<u32>) -> Vec<u32> {
        let mut lines: Vec<u32> = slice.into_iter().collect();
        lines.sort_unstable();
        lines
    }

    #[test]
    fn slice_keeps_multiline_signature_together() {
        // GIVEN: a multi-line `def` where each parameter is defined on its own
        // row, and a body that uses one of them.
        let source = "\nclass Foo:\n    def __init__(\n        self,\n        a,\n        b,\n        c=None,\n    ):\n        self.a = a\n        self.b = b\n        self.c = c\n        for i in range(5):\n            self.a += i\n        return None\n";

        // WHEN: we slice backward from `self.a = a`
        let lines = sorted(
            get_slice(
                source,
                "__init__",
                9,
                SliceDirection::Backward,
                None,
                Language::Python,
            )
            .unwrap(),
        );

        // THEN: the WHOLE signature comes along, and the unrelated loop does not.
        //
        // why the whole signature (TRDD-3TCJKGWM): a one-node-per-LINE PDG put
        // the def of `a` on line 5 and nothing else, so this slice returned
        // {5, 9} — it dropped rows 3,4,6,7,8 of the very statement that
        // defines `a`. A signature is one program point; splitting it is
        // unsound, not merely coarse.
        assert_eq!(lines, vec![3, 4, 5, 6, 7, 8, 9]);
        // The precision half, pinned line by line: everything from the `for`
        // header (12) to the end of the function (14) is downstream of the
        // criterion, so a graph that went coarse again — one node over the
        // whole entry block, as HEAD's block-granular builder had — would
        // drag these in. `10`/`11` are the sibling assignments, equally out.
        for unrelated in [10, 11, 12, 13, 14] {
            assert!(
                !lines.contains(&unrelated),
                "line {unrelated} does not feed `self.a = a`"
            );
        }
    }

    #[test]
    fn forward_slice_stops_at_the_statements_a_parameter_reaches() {
        // GIVEN: the same multi-line-signature fixture.
        let source = "\nclass Foo:\n    def __init__(\n        self,\n        a,\n        b,\n        c=None,\n    ):\n        self.a = a\n        self.b = b\n        self.c = c\n        for i in range(5):\n            self.a += i\n        return None\n";

        // WHEN: we slice FORWARD from the signature
        let lines = sorted(
            get_slice(
                source,
                "__init__",
                3,
                SliceDirection::Forward,
                None,
                Language::Python,
            )
            .unwrap(),
        );

        // THEN: `return None` (the last body line) reads nothing the signature
        // defines, so it must not appear. This is the precision side: a single
        // node covering the whole entry block would sweep it in.
        assert!(
            !lines.contains(&14),
            "`return None` depends on no parameter (got {lines:?})"
        );
    }

    #[test]
    fn slice_is_sound_across_multiline_call() {
        // GIVEN: an assignment whose call arguments sit on their own rows.
        let source = "\ndef f(a, b):\n    x = compute(\n        a,\n        b,\n    )\n    y = 7\n    return x\n";

        // WHEN: we slice backward from `return x`
        let lines = sorted(
            get_slice(
                source,
                "f",
                8,
                SliceDirection::Backward,
                None,
                Language::Python,
            )
            .unwrap(),
        );

        // THEN: the whole `x = compute(a, b)` statement AND the signature that
        // defines `a`/`b` are present; the unrelated `y = 7` is not.
        //
        // why (TRDD-3TCJKGWM): the per-line PDG returned {3, 8} — the uses of
        // `a` and `b` landed on rows 4 and 5, which were nodes disconnected
        // from the row holding the def of `x`, so the backward walk never
        // reached line 2 at all.
        assert_eq!(lines, vec![2, 3, 4, 5, 6, 8]);
        assert!(!lines.contains(&7), "`y = 7` feeds nothing here");
    }

    #[test]
    fn slice_keeps_multiline_signature_together_rust() {
        // GIVEN: a Rust fn whose `)` shares a row with the return type — the
        // case where "everything above the body" would clip the signature.
        let source = "\nfn f(\n    a: u32,\n    b: u32,\n) -> u32 {\n    let x = a + b;\n    let y = 7;\n    return x;\n}\n";

        let lines = sorted(
            get_slice(
                source,
                "f",
                8,
                SliceDirection::Backward,
                None,
                Language::Rust,
            )
            .unwrap(),
        );

        assert_eq!(lines, vec![2, 3, 4, 5, 6, 8]);
        assert!(!lines.contains(&7), "`let y = 7` feeds nothing here");
    }

    #[test]
    fn slice_keeps_multiline_signature_together_typescript() {
        // GIVEN: the same shape in TypeScript.
        let source = "\nfunction f(\n  a: number,\n  b: number,\n): number {\n  const x = a + b;\n  const y = 7;\n  return x;\n}\n";

        let lines = sorted(
            get_slice(
                source,
                "f",
                8,
                SliceDirection::Backward,
                None,
                Language::TypeScript,
            )
            .unwrap(),
        );

        assert_eq!(lines, vec![2, 3, 4, 5, 6, 8]);
        assert!(!lines.contains(&7), "`const y = 7` feeds nothing here");
    }
}

// =============================================================================
// Edge Case Tests
// =============================================================================

mod pdg_edge_case_tests {
    use super::*;

    #[test]
    fn pdg_handles_try_except() {
        // GIVEN: A function with exception handling
        let source = r#"
def risky():
    try:
        x = dangerous()
    except:
        x = fallback()
    return x
"#;

        // WHEN: We extract the PDG
        let pdg = get_pdg_context(source, "risky", Language::Python).unwrap();

        // THEN: Should be constructed successfully
        assert!(!pdg.nodes.is_empty(), "PDG should handle try/except");
    }

    #[test]
    fn pdg_handles_recursive_function() {
        // GIVEN: A recursive function
        let source = r#"
def factorial(n):
    if n <= 1:
        return 1
    return n * factorial(n - 1)
"#;

        // WHEN: We extract the PDG
        let pdg = get_pdg_context(source, "factorial", Language::Python).unwrap();

        // THEN: Should be constructed successfully
        assert!(
            !pdg.nodes.is_empty(),
            "PDG should handle recursive functions"
        );
    }

    #[test]
    fn pdg_handles_nested_functions() {
        // GIVEN: A function with nested definition
        let source = r#"
def outer():
    def inner():
        return 1
    return inner()
"#;

        // WHEN: We extract the PDG
        let pdg = get_pdg_context(source, "outer", Language::Python).unwrap();

        // THEN: Should be constructed successfully
        assert!(!pdg.nodes.is_empty(), "PDG should handle nested functions");
    }

    #[test]
    fn pdg_handles_large_function() {
        // GIVEN: A large function with many statements
        let mut source = String::from("def large():\n");
        for i in 0..50 {
            source.push_str(&format!("    x{} = {}\n", i, i));
        }
        source.push_str("    return x0\n");

        // WHEN: We extract the PDG
        let pdg = get_pdg_context(&source, "large", Language::Python).unwrap();

        // THEN: Should be constructed successfully
        assert!(!pdg.nodes.is_empty(), "PDG should handle large functions");
    }

    #[test]
    fn pdg_handles_single_line_function() {
        // GIVEN: A single-line function
        let source = "def tiny(): return 42";

        // WHEN: We extract the PDG
        let pdg = get_pdg_context(source, "tiny", Language::Python).unwrap();

        // THEN: Should be constructed successfully
        assert!(
            !pdg.nodes.is_empty(),
            "PDG should handle single-line functions"
        );
    }
}
