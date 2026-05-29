//! cpp-python-ast-issues-v1 (v0.4.2 M-106)
//!
//! Regression tests for three open issues located by Phase-22 iter-2:
//!
//! - #46 — C++ enums missing from `structure` output. `extract_classes` only
//!   dispatched `extract_c_structs` for `Language::C`, never `Cpp`. Also
//!   `enum_specifier` was absent from `classify_definition_node`, so enums
//!   were dropped from `definitions[]` as well.
//!
//! - #47 — `find_cpp_qualified_function_definition` used BFS
//!   (`VecDeque::push_back` / `pop_front`), which returned the SHALLOWEST
//!   match in AST order rather than the FIRST match in source order. For a
//!   file containing two definitions of `Foo::bar` — one nested deep in
//!   namespaces (earlier in source) and one at top level (later in source)
//!   — the resolver returned the later top-level form, mis-routing slice /
//!   complexity / explain / contracts / taint downstream.
//!
//! - #48 — `context::builder::get_cfg_metrics` extracted the bare method
//!   name with `func_name.rfind('.')`, which:
//!     * For Python `Class.method`: stripped to `method`, then the bare CFG
//!       lookup matched the FIRST `method` in the file — producing
//!       `blocks` from a sibling class while `cyclomatic` (which goes
//!       through `calculate_complexity` with the qualified name) stayed
//!       correct. Result: inconsistent `blocks` vs `cyclomatic` for the
//!       same record.
//!     * For C++ `Class::method`: `rfind('.')` returns `None`, so the
//!       qualified form was passed through. C++ was accidentally
//!       unaffected by the existing bug shape, but the same record would
//!       also break if `Class.method` was supplied (cross-language
//!       fallthrough — e.g. by a wrapper using a normalized separator).
//!   Fix: pass the qualified name straight through to `get_cfg_context`
//!   (which already understands both `.` and `::` qualified forms via
//!   `find_function_node`), only falling back to the bare last segment
//!   when the qualified lookup returns an empty CFG.
//!
//! All three tests use the public library API (no subprocess) so they
//! integrate with the workspace `cargo test`.

use std::fs;
use tempfile::TempDir;

use tldr_core::ast::get_code_structure;
use tldr_core::cfg::get_cfg_context;
use tldr_core::context::get_relevant_context;
use tldr_core::types::Language;

// ============================================================================
// Issue #46 — C++ enums must appear in structure `classes[]` AND `definitions[]`
// ============================================================================

#[test]
fn test_46_cpp_enum_only_file_emits_enums_in_structure() {
    // Hermetic fixture matching the iter-2 repro (cpp_enum_only.cpp).
    let src = "enum class Status { Ok, Err };\n\
               enum Color { Red, Green };\n";

    let tmp = TempDir::new().unwrap();
    let file = tmp.path().join("enum_only.cpp");
    fs::write(&file, src).unwrap();

    let result = get_code_structure(&file, Language::Cpp, 1000, None)
        .expect("structure extraction failed");

    assert_eq!(result.files.len(), 1, "expected one file in result");
    let f = &result.files[0];

    // `classes[]` should contain both enum names (treated as types alongside
    // structs/classes for the purposes of the structure summary).
    assert!(
        f.classes.iter().any(|c| c == "Status"),
        "expected `Status` enum in classes[] but got: {:?}",
        f.classes
    );
    assert!(
        f.classes.iter().any(|c| c == "Color"),
        "expected `Color` enum in classes[] but got: {:?}",
        f.classes
    );

    // `definitions[]` should also carry the enums (kind="enum" preferred,
    // but at minimum the names must be present).
    let def_names: Vec<&str> = f.definitions.iter().map(|d| d.name.as_str()).collect();
    assert!(
        def_names.contains(&"Status"),
        "expected `Status` in definitions[] but got: {:?}",
        def_names
    );
    assert!(
        def_names.contains(&"Color"),
        "expected `Color` in definitions[] but got: {:?}",
        def_names
    );

    // And the enum kind classification must be `enum`, not `class`.
    for def in f.definitions.iter().filter(|d| d.name == "Status" || d.name == "Color") {
        assert_eq!(
            def.kind, "enum",
            "expected kind=\"enum\" for {} but got kind={:?}",
            def.name, def.kind
        );
    }
}

#[test]
fn test_46_cpp_mixed_enums_and_classes() {
    // A more realistic mix: enums alongside class + struct + free function.
    let src = "enum class Color { Red, Green, Blue };\n\
               enum Style { Bold, Italic };\n\
               class Widget {\n\
               public:\n\
                   void draw();\n\
               };\n\
               struct Point { int x; int y; };\n";

    let tmp = TempDir::new().unwrap();
    let file = tmp.path().join("mixed.cpp");
    fs::write(&file, src).unwrap();

    let result = get_code_structure(&file, Language::Cpp, 1000, None)
        .expect("structure extraction failed");

    let f = &result.files[0];

    // All four types must be present in classes[]
    for expected in &["Color", "Style", "Widget", "Point"] {
        assert!(
            f.classes.iter().any(|c| c == expected),
            "expected `{}` in classes[] but got: {:?}",
            expected,
            f.classes
        );
    }

    // Same for definitions[] (name presence only — kinds vary)
    let def_names: Vec<&str> = f.definitions.iter().map(|d| d.name.as_str()).collect();
    for expected in &["Color", "Style", "Widget", "Point"] {
        assert!(
            def_names.contains(expected),
            "expected `{}` in definitions[] but got: {:?}",
            expected,
            def_names
        );
    }
}

// ============================================================================
// Issue #47 — DFS pre-order: first source-order qualified definition wins
// ============================================================================

#[test]
fn test_47_cpp_qualified_resolution_returns_source_order_first_not_shallowest() {
    // Two definitions of Foo::bar:
    //   - Lines 4-6: nested deep inside `outer::inner` namespaces (earlier
    //     in source, DEEPER in AST).
    //   - Lines 11-13: top-level (later in source, SHALLOWER in AST).
    //
    // BFS returns the shallower one first (line 11). DFS pre-order should
    // return the deeper one first (line 4) because it comes first in
    // source order.
    let src = "namespace outer {\n\
                  namespace inner {\n\
                      // earlier in source, deeper in AST\n\
                      int Foo::bar() {\n\
                          return 1;\n\
                      }\n\
                  }\n\
              }\n\
              \n\
              // later in source, shallower in AST\n\
              int Foo::bar() {\n\
                  return 2;\n\
              }\n";

    let tmp = TempDir::new().unwrap();
    let file = tmp.path().join("bfs2.cpp");
    fs::write(&file, src).unwrap();

    // `get_cfg_context` resolves `Foo::bar` via `find_function_node` →
    // `find_cpp_qualified_function_definition`. We assert that the FIRST
    // definition picked up (the namespaced one) covers line 5, NOT the
    // shallow one which covers line 12.
    let cfg = get_cfg_context(file.to_str().unwrap(), "Foo::bar", Language::Cpp)
        .expect("cfg ok");

    // The cfg must be non-empty for the correct first-source-order match.
    assert!(
        !cfg.blocks.is_empty(),
        "expected non-empty CFG for Foo::bar, got blocks={}",
        cfg.blocks.len()
    );

    // Each block in the CFG records source line ranges. Collect every
    // (start, end) range that appears in any block and assert that line 5
    // (inside the namespaced definition, lines 4-6) falls within some
    // block range — and that line 12 (inside the shallow definition,
    // lines 11-13) does NOT.
    let in_range = |line: u32, start: u32, end: u32| -> bool {
        line >= start && line <= end
    };

    let has_line_5 = cfg
        .blocks
        .iter()
        .any(|b| in_range(5, b.lines.0, b.lines.1));
    let has_line_12 = cfg
        .blocks
        .iter()
        .any(|b| in_range(12, b.lines.0, b.lines.1));

    assert!(
        has_line_5,
        "DFS pre-order should pick the namespaced (line 4-6) Foo::bar definition; \
         no block in returned CFG covers line 5. \
         blocks: {:?}",
        cfg.blocks.iter().map(|b| b.lines).collect::<Vec<_>>()
    );
    assert!(
        !has_line_12,
        "DFS pre-order should NOT pick the shallow (line 11-13) Foo::bar definition; \
         a block in returned CFG covers line 12 (BFS-style shallowest-first behavior). \
         blocks: {:?}",
        cfg.blocks.iter().map(|b| b.lines).collect::<Vec<_>>()
    );
}

// ============================================================================
// Issue #48 — context CFG metrics: bare-name fallback mis-resolves qualified methods
// ============================================================================

/// Builds a one-file project where two classes share a method name `process`;
/// `Beta::process` is complex (nested if + while → many blocks), `Alpha::process`
/// is trivial. Then asks `get_relevant_context` for `Alpha::process` (cpp) or
/// `Alpha.process` (python) and asserts that the `blocks` field comes from
/// Alpha (the qualified target), not from Beta (the first source-order bare
/// `process`).
fn assert_qualified_method_blocks_match_target(
    lang: Language,
    file_name: &str,
    src: &str,
    qualified: &str,
) {
    // The Python call-graph builder is heavily recursive and the default
    // cargo test worker thread (2 MB on macOS) is not enough to run it on
    // even moderate-size projects — wrap the actual work in a thread with
    // an explicit 16 MB stack, matching `main()` defaults.
    let lang_owned = lang;
    let file_name_owned = file_name.to_string();
    let src_owned = src.to_string();
    let qualified_owned = qualified.to_string();

    let result: (usize, u32) = std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(move || {
            let tmp = TempDir::new().unwrap();
            let file = tmp.path().join(&file_name_owned);
            fs::write(&file, &src_owned).unwrap();

            // Pass an absolute file_filter path — same shape as CLI `--file`.
            let ctx = get_relevant_context(
                tmp.path(),
                &qualified_owned,
                0,
                lang_owned,
                false,
                Some(&file),
            )
            .unwrap_or_else(|e| {
                panic!("get_relevant_context({}) failed: {:?}", qualified_owned, e)
            });

            assert!(
                !ctx.functions.is_empty(),
                "expected at least one function in context for {}; got 0",
                qualified_owned
            );
            let entry = &ctx.functions[0];

            let blocks = entry
                .blocks
                .expect("expected `blocks` to be populated for the entry function");
            let cyclo = entry
                .cyclomatic
                .expect("expected `cyclomatic` to be populated for the entry function");
            (blocks, cyclo)
        })
        .unwrap()
        .join()
        .unwrap();

    let (blocks, cyclo) = result;

    // Alpha::process / Alpha.process is trivial: cyclomatic = 1, and the
    // CFG should contain only a small number of basic blocks.
    // Beta::process has nested if + while → cyclomatic 5, blocks ~14.
    // The bug: pre-fix Python returns Alpha's cyclomatic (1, correct
    // because the cyclomatic path uses the qualified name) but Beta's
    // blocks (~14, wrong) because the blocks path stripped to bare
    // `process` and matched Beta first.
    assert_eq!(
        cyclo, 1,
        "expected cyclomatic=1 for Alpha::process (target trivial); got {}",
        cyclo
    );
    assert!(
        blocks < 10,
        "expected `blocks` for Alpha::process to be small (target trivial), \
         got blocks={} — likely measuring Beta::process instead. \
         cyclomatic was {} (correct), blocks is the broken metric.",
        blocks,
        cyclo
    );
}

#[test]
fn test_48_cpp_qualified_method_blocks_match_target() {
    // Same shape as cpp_ctx48.cpp from iter-2.
    let src = "class Beta {\n\
                public:\n\
                    void process() {\n\
                        int a = 1;\n\
                        if (a > 0) {\n\
                            if (a > 1) {\n\
                                if (a > 2) {\n\
                                    a++;\n\
                                }\n\
                            }\n\
                        }\n\
                        while (a < 100) {\n\
                            a++;\n\
                        }\n\
                    }\n\
                };\n\
                \n\
                class Alpha {\n\
                public:\n\
                    void process() {\n\
                        int x = 1;\n\
                        return;\n\
                    }\n\
                };\n";
    assert_qualified_method_blocks_match_target(
        Language::Cpp,
        "ctx48.cpp",
        src,
        "Alpha::process",
    );
}

// NOTE: The Python case for #48 is covered by a unit test in
// `crates/tldr-core/src/context/builder.rs::tests::
//  test_48_python_get_cfg_metrics_qualified_method` because the rayon
// worker threads used by `build_project_call_graph` carry a default
// stack size too small to drive the full integration path under
// `cargo test` on macOS, whereas the unit test inside the `context::builder`
// module can exercise the private `get_cfg_metrics` directly without
// touching the call-graph builder.
