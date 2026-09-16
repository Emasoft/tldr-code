//! p19-secondary-fixes-v1 (BUG-P19-02..09)
//!
//! 8 secondary defects from the phase-19 aggregate audit:
//!
//!  - BUG-P19-02: Rust `max_nesting` permanently 0 across the corpus
//!                (Rust grammar uses `*_expression` shape that the
//!                cognitive walker's nesting set didn't recognise).
//!  - BUG-P19-03: OCaml `cognitive` lists every function twice (the
//!                walker matches both `value_definition` and inner
//!                `let_binding`, emitting (name, line) duplicates).
//!  - BUG-P19-04: C++ `XMLClass::ParseDeep` overloads all reported
//!                identical metrics — bare-name fallback returned the
//!                first match for all 7 overloads.
//!  - BUG-P19-05: `tldr structure tinyxml2.h --lang cpp` reported enums
//!                as classes and missed all macro-prefixed real
//!                classes; `parse_file()` ignored the `--lang cpp` hint
//!                and re-detected `.h` → C.
//!  - BUG-P19-06: `tldr definition` always emitted `column: 0` because
//!                `FuncDef`/`ClassDef` only carry the line number.
//!  - BUG-P19-07: cpp `complexity` and `context` reported different
//!                cyclomatic for the same function (two distinct
//!                decision counters).
//!  - BUG-P19-08: cpp class count drifted across `structure`,
//!                `interface`, and `health` for the same input.
//!  - BUG-P19-09: Rust `specs --from-tests` extracted specs from only
//!                1/6 test functions because `assert!(call(...))`
//!                shape was unrecognised (`call_expression` wrapper is
//!                missing inside Rust macro `token_tree`).
//!
//! Real-repo gated per no-synthetic-fixtures-v1: each test returns
//! early when its `/tmp/repos/<repo>` corpus is absent and otherwise
//! asserts numeric thresholds against hand-counted ground truth.

use std::path::Path;
use std::process::Command;

fn tldr_bin() -> std::path::PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR must be set under cargo test");
    std::path::PathBuf::from(manifest)
        .join("..")
        .join("..")
        .join("target")
        .join("release")
        .join("tldr")
}

fn run_tldr(args: &[&str]) -> (i32, String) {
    let out = Command::new(tldr_bin())
        .args(args)
        .output()
        .expect("failed to run tldr binary");
    let exit = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    (exit, stdout)
}

fn parse_json(out: &str) -> serde_json::Value {
    serde_json::from_str(out).unwrap_or(serde_json::Value::Null)
}

// ============================================================================
// BUG-P19-02: Rust max_nesting permanently 0
// ============================================================================
#[test]
fn p19_bug02_rust_max_nesting_distribution_not_collapsed() {
    let file = "/tmp/repos/ripgrep/crates/globset/src/glob.rs";
    if !Path::new(file).exists() {
        return;
    }
    let (rc, out) = run_tldr(&["cognitive", file, "--format", "json"]);
    assert_eq!(rc, 0);
    let v = parse_json(&out);
    let unique_nesting: std::collections::HashSet<u64> = v["functions"]
        .as_array()
        .map(|a| a.iter().filter_map(|f| f["max_nesting"].as_u64()).collect())
        .unwrap_or_default();
    // Pre-fix the unique set was `{0}` (50/50 functions reported 0).
    // Post-fix it should span at least 3 distinct depths.
    assert!(
        unique_nesting.len() >= 3,
        "rust max_nesting must span >=3 distinct depths across glob.rs; \
         got {:?}",
        unique_nesting
    );
    assert!(
        unique_nesting.iter().any(|n| *n >= 2),
        "at least one rust function must report max_nesting >= 2; got {:?}",
        unique_nesting
    );
}

// ============================================================================
// BUG-P19-03: OCaml AST double-walk (dedup by (name, line))
// ============================================================================
#[test]
fn p19_bug03_ocaml_no_same_name_same_line_duplicates() {
    let file = "/tmp/repos/ocaml-dune/src/dune_engine/action_exec.ml";
    if !Path::new(file).exists() {
        return;
    }
    let (rc, out) = run_tldr(&["cognitive", file, "--format", "json"]);
    assert_eq!(rc, 0);
    let v = parse_json(&out);
    // Collect (name, line) pairs and verify NO duplicate.
    let mut seen: std::collections::HashSet<(String, u64)> = std::collections::HashSet::new();
    let mut dupes = 0usize;
    for f in v["functions"].as_array().cloned().unwrap_or_default() {
        let name = f["name"].as_str().unwrap_or("").to_string();
        let line = f["line"].as_u64().unwrap_or(0);
        if !seen.insert((name.clone(), line)) {
            dupes += 1;
        }
    }
    assert_eq!(
        dupes, 0,
        "ocaml `cognitive` must not emit duplicate (name, line) entries; \
         got {} duplicates across action_exec.ml",
        dupes
    );
}

// ============================================================================
// BUG-P19-04: C++ overload disambiguation (each ParseDeep gets distinct
// metrics matching its actual definition)
// ============================================================================
#[test]
fn p19_bug04_cpp_parsedeep_overloads_distinct() {
    let file = "/tmp/repos/cpp-tinyxml2/tinyxml2.cpp";
    if !Path::new(file).exists() {
        return;
    }
    let mut cycs: Vec<u64> = Vec::new();
    for cls in ["XMLNode", "XMLText", "XMLElement", "XMLComment"] {
        let qualified = format!("{}::ParseDeep", cls);
        let (rc, out) = run_tldr(&["complexity", file, &qualified, "--format", "json"]);
        assert_eq!(rc, 0, "tldr complexity {} rc != 0; out={}", qualified, out);
        let v = parse_json(&out);
        if let Some(c) = v["cyclomatic"].as_u64() {
            cycs.push(c);
        }
    }
    let unique: std::collections::HashSet<u64> = cycs.iter().copied().collect();
    assert!(
        unique.len() >= 3,
        "cpp ::ParseDeep overloads must disambiguate to distinct metrics; \
         got cyclomatic={:?}",
        cycs
    );
}

// ============================================================================
// BUG-P19-05: `structure --lang cpp` returns real classes (not enums)
// ============================================================================
#[test]
fn p19_bug05_cpp_structure_returns_real_classes() {
    let file = "/tmp/repos/cpp-tinyxml2/tinyxml2.h";
    if !Path::new(file).exists() {
        return;
    }
    let (rc, out) = run_tldr(&["structure", file, "--lang", "cpp", "--format", "json"]);
    assert_eq!(rc, 0);
    let v = parse_json(&out);
    let classes: Vec<String> = v["files"][0]["classes"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|c| c.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    // Real cpp classes (must be present)
    for expected in &["XMLDocument", "XMLElement", "XMLNode"] {
        assert!(
            classes.iter().any(|c| c == expected),
            "cpp `structure` must report real class `{}` in tinyxml2.h; \
             got classes={:?}",
            expected,
            classes
        );
    }
    // Pre-fix output included `Mode` (an enum) — must be gone.
    assert!(
        !classes.iter().any(|c| c == "Mode" || c == "XMLError"),
        "cpp `structure` must NOT report enum names (Mode/XMLError) as classes; \
         got classes={:?}",
        classes
    );
}

// ============================================================================
// BUG-P19-06: `definition` reports a non-zero (1-indexed) column
// ============================================================================
#[test]
fn p19_bug06_definition_column_not_zero() {
    let file = "/tmp/repos/ripgrep/crates/globset/src/glob.rs";
    if !Path::new(file).exists() {
        return;
    }
    let (rc, out) = run_tldr(&[
        "definition",
        "--symbol",
        "parse",
        "--file",
        file,
        "--format",
        "json",
    ]);
    assert_eq!(rc, 0);
    let v = parse_json(&out);
    let col = v["definition"]["column"].as_u64().unwrap_or(0);
    assert!(
        col > 0,
        "`definition --symbol parse` must report a non-zero (1-indexed) \
         column; got {}",
        col
    );
}

// ============================================================================
// BUG-P19-07: complexity and context agree on cyclomatic
// ============================================================================
#[test]
fn p19_bug07_complexity_and_context_agree_on_cyclomatic() {
    let cpp_file = "/tmp/repos/cpp-tinyxml2/tinyxml2.cpp";
    let cpp_repo = "/tmp/repos/cpp-tinyxml2";
    if !Path::new(cpp_file).exists() {
        return;
    }
    let func = "XMLDocument::Parse";
    let (rc1, complexity_out) = run_tldr(&["complexity", cpp_file, func, "--format", "json"]);
    assert_eq!(rc1, 0);
    let v1 = parse_json(&complexity_out);
    let cyc_complexity = v1["cyclomatic"].as_u64();

    let (rc2, context_out) = run_tldr(&["context", func, cpp_repo, "--format", "json"]);
    assert_eq!(rc2, 0);
    let v2 = parse_json(&context_out);
    let cyc_context = v2["functions"].as_array().and_then(|a| {
        a.iter()
            .find(|f| f["name"].as_str() == Some(func))
            .and_then(|f| f["cyclomatic"].as_u64())
    });

    assert!(
        cyc_complexity.is_some() && cyc_context.is_some(),
        "both pipelines must report cyclomatic for {}; got complexity={:?} \
         context={:?}",
        func,
        cyc_complexity,
        cyc_context
    );
    assert_eq!(
        cyc_complexity, cyc_context,
        "complexity and context must report the same cyclomatic for {}; \
         got complexity={:?} context={:?}",
        func, cyc_complexity, cyc_context
    );
}

// ============================================================================
// BUG-P19-08: cpp class count consistency across structure / interface / health
// ============================================================================
#[test]
fn p19_bug08_cpp_class_count_consistency() {
    let file = "/tmp/repos/cpp-tinyxml2/tinyxml2.h";
    if !Path::new(file).exists() {
        return;
    }
    let (rc1, s_out) = run_tldr(&["structure", file, "--lang", "cpp", "--format", "json"]);
    assert_eq!(rc1, 0);
    let structure_count = parse_json(&s_out)["files"][0]["classes"]
        .as_array()
        .map(|a| a.len())
        .unwrap_or(0);
    let (rc2, i_out) = run_tldr(&["interface", file, "--format", "json"]);
    assert_eq!(rc2, 0);
    let interface_count = parse_json(&i_out)["classes"]
        .as_array()
        .map(|a| a.len())
        .unwrap_or(0);
    let (rc3, h_out) = run_tldr(&["health", file, "--format", "json"]);
    assert_eq!(rc3, 0);
    let health_count = parse_json(&h_out)["summary"]["classes_analyzed"]
        .as_u64()
        .unwrap_or(0) as usize;

    // Pre-fix: structure=6 (enums-as-classes), interface=26, health=0.
    // Post-fix: all three within +/-2 of each other (forward-decl + body
    // pairs may add a single delta to the structure surface).
    assert!(
        structure_count >= 20,
        "structure cpp class count must be >= 20; got {}",
        structure_count
    );
    assert!(
        interface_count >= 20,
        "interface cpp class count must be >= 20; got {}",
        interface_count
    );
    assert!(
        health_count >= 20,
        "health cpp class count must be >= 20 (BUG-P19-08); got {}",
        health_count
    );
    let max = structure_count.max(interface_count).max(health_count);
    let min = structure_count.min(interface_count).min(health_count);
    assert!(
        max - min <= 4,
        "structure/interface/health cpp class counts must agree within \
         4; got structure={} interface={} health={}",
        structure_count,
        interface_count,
        health_count
    );
}

// ============================================================================
// BUG-P19-09: `specs --from-tests` recall extension for `assert!(call(...))`
// ============================================================================
#[test]
fn p19_bug09_specs_recall_assert_macro_calls() {
    let file = "/tmp/repos/ripgrep/crates/globset/src/lib.rs";
    if !Path::new(file).exists() {
        return;
    }
    let (rc, out) = run_tldr(&["specs", "--from-tests", file, "--format", "json"]);
    assert_eq!(rc, 0);
    let v = parse_json(&out);
    let fns: Vec<String> = v["functions"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|f| f["function_name"].as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    let total_specs = v["summary"]["total_specs"].as_u64().unwrap_or(0);

    // Pre-fix: only `escape` recognised → 1 function / 7 specs.
    // Post-fix: at least `is_match` and `matches_all` also surface from
    // the `assert!(set.is_match(...))` shape.
    assert!(
        fns.len() >= 2,
        "specs --from-tests on globset/src/lib.rs must surface >= 2 \
         functions; got {:?}",
        fns
    );
    assert!(
        total_specs >= 10,
        "specs --from-tests on globset/src/lib.rs must surface >= 10 specs; \
         got {}",
        total_specs
    );
}
