//! cross-cutting-and-clear-fix-bugs-v1 (P18): closes 7 of the 8 distinct
//! non-judgment-call bugs flagged by the phase-18 final-review aggregate.
//! The 8th (Bug 7 — kotlin specs functions[].name=null) was already fixed
//! at HEAD; the test for it pins the schema so a future regression cannot
//! re-introduce the empty-emitter behaviour.
//!
//!   1. **P18.X3 (lua FuncIndex `function m.foo` resolver)** —
//!      `tldr impact m.open /tmp/repos/lua-lsp` previously returned
//!      `caller_count: 0` (and `whatbreaks` 0/0/0) even though
//!      `tldr explain script/files.lua m.open` reported 18 cross-module
//!      callers via the P13.AGG13-12 references-enrichment path. Fix:
//!      mirror the same Lua bare-name retry inside
//!      `enrich_impact_with_references` so impact / whatbreaks pick up
//!      the same call sites explain already finds.
//!
//!   2. **P18.B1 (scala reaching-defs flags fn params, `this`,
//!      companion objects)** — `tldr reaching-defs IO.scala flatMap`
//!      previously flagged `f` (a function parameter), `this`, and the
//!      companion-object identifiers `IO`, `FlatMap`, `Tracing` as
//!      `severity: definite` uninitialized. Fix: (a) add Scala parameter
//!      extraction to the dfg dispatch (the previous code-path returned
//!      the type-parameters node for the field name `parameters` rather
//!      than the value-parameter list, so no params were recorded as
//!      definitions), (b) add a Scala arm to `is_keyword` so `this`
//!      isn't classified as an identifier use, and (c) suppress
//!      identifiers whose first letter is uppercase (Scala convention
//!      for types, classes, and companion objects) at the use-context
//!      gate, plus the `field_expression`'s `field` member name.
//!
//!   3. **P18.R2 (swift `impact`/`whatbreaks` fabricates test-file
//!      location for `Heap._heapify`)** —
//!      `tldr impact _heapify /tmp/repos/swift-collections` previously
//!      emitted a target row with `file: Tests/HeapTests/HeapTests.swift`
//!      for `Heap._heapify` even though the test file does not define
//!      `_heapify` at all. Fix: in
//!      `impact_analysis_with_ast_fallback`, when AST has authoritative
//!      knowledge of where the function is defined, drop call-graph-
//!      derived target rows whose file is NOT in the AST set. Swift-
//!      gated to avoid disturbing other languages.
//!
//!   4. **P18.X4 (TypeScript dir-walker fails on `src/` when single
//!      subdir + empty siblings)** —
//!      `tldr loc /tmp/repos/ts-dom-gen/src` previously returned
//!      `total_files: 0` because `src/` only contains `build/` and
//!      `build` is in the default-skip list before the JS/TS hint can
//!      be derived. Fix: (a) make `Language::from_directory` retry with
//!      `no_default_ignore` when the first pass yields zero files, so
//!      JS/TS layouts whose only sources live under `build/`/`dist/`
//!      get their dominant language correctly identified; (b) add an
//!      auto-JS/TS-preserve flag to `ProjectWalker::iter` for layouts
//!      where the unfiltered file count is JS/TS-dominant; (c) thread
//!      a JS/TS hint through `loc`'s direct `WalkBuilder` path via a
//!      new `should_skip_path_with_lang` helper.
//!
//!   5. **P18.X1 (halstead duplicate-emission for java + elixir)** —
//!      The Java AST extractor emits class methods as BOTH
//!      `module.functions` AND `module.classes[].methods`. Halstead
//!      walked both surfaces and pushed one entry each. The Elixir
//!      extractor does the same for module functions. Fix:
//!      `analyze_halstead` now dedups by `(name, file, line)` after
//!      the loops complete, plus a parallel dedup for violations.
//!
//!   6. **P18.Pattern-B (bare+qualified duplicate emission)** —
//!      Three distinct surfaces were affected: (a) swift `explain`'s
//!      callees emitted both `trickleDownMin` (from `find_callees`) and
//!      `Heap.trickleDownMin` (from `enrich_with_project_graph`) for
//!      the same call site; (b) csharp `todo` emitted both bare and
//!      `Class.method` shapes for the same complexity finding; (c)
//!      java `structure` emitted `private static final String FOO = ...`
//!      twice — once as `kind: constant`, once as `kind: field`.
//!      Fix: line-aware bare-vs-qualified dedup in
//!      `find_callees_recursive` and `enrich_with_project_graph`;
//!      `(category, file, line)` dedup in the todo emitter; and skip
//!      the field-detection path in `collect_definitions` when the
//!      same node was already emitted as a constant.
//!
//!   7. **P18.KOT-3 (kotlin specs --from-tests emitter)** — already
//!      fixed at HEAD `3bcd65e`: the canonical schema uses
//!      `function_name` (not `name`) and split spec arrays
//!      (`input_output_specs` / `exception_specs` / `property_specs`),
//!      and on `kotlin-datetime/InstantTest.kt` the first function
//!      entry is `DateTimePeriod` with at least one spec. The audit
//!      report referred to stale field names. The test pins the
//!      schema so a future regression cannot reintroduce the empty
//!      emitter.
//!
//!   8. **P18.B8 (scala importers brace-list line accuracy)** —
//!      `tldr importers cats.effect.tracing.Tracing
//!      /tmp/repos/scala-cats-effect` previously reported the
//!      brace-list import in `cats/effect/IO.scala` at line 1 (the
//!      synthetic fallback) instead of the actual line 52 because
//!      `find_import_line`'s substring check (`trimmed.contains(module)`)
//!      cannot match the literal module string against the brace-list
//!      shape (`cats.effect.tracing.{Tracing, TracingEvent}`). Fix:
//!      Scala-specific brace-list parser that splits on `,` (and
//!      handles the rename arrow `X => Y`) for both single-line and
//!      multi-line braces.
//!
//! Per `no-synthetic-fixtures-v1`: every test gates on real-repo
//! presence (`/tmp/repos/<repo>`) and uses numeric thresholds the
//! canonical real-repo material guarantees.

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
// Bug 1 (P18.X3): lua impact / whatbreaks must surface ≥ 18 callers for
// `m.open` (matching the explain count). Pre-fix: 0/0.
// ============================================================================

#[test]
fn p18_x3_lua_impact_m_open_callers_match_explain() {
    let repo = "/tmp/repos/lua-lsp";
    if !Path::new(repo).exists() {
        return;
    }
    let (rc, out) = run_tldr(&["impact", "m.open", repo, "--format", "json"]);
    assert_eq!(rc, 0, "tldr impact rc != 0; stdout={}", out);
    let v = parse_json(&out);
    let total_callers: usize = v["targets"]
        .as_object()
        .map(|m| {
            m.values()
                .map(|t| t["callers"].as_array().map(|a| a.len()).unwrap_or(0))
                .sum()
        })
        .unwrap_or(0);
    assert!(
        total_callers >= 18,
        "expected at least 18 m.open callers via impact (matches explain), got {}",
        total_callers
    );
}

#[test]
fn p18_x3_lua_whatbreaks_m_open_direct_callers_nonzero() {
    let repo = "/tmp/repos/lua-lsp";
    if !Path::new(repo).exists() {
        return;
    }
    let (rc, out) = run_tldr(&["whatbreaks", "m.open", repo, "--format", "json"]);
    assert_eq!(rc, 0, "tldr whatbreaks rc != 0; stdout={}", out);
    let v = parse_json(&out);
    let direct = v["summary"]["direct_caller_count"].as_u64().unwrap_or(0);
    assert!(
        direct >= 1,
        "expected direct_caller_count >= 1 for m.open via whatbreaks, got {}",
        direct
    );
}

// ============================================================================
// Bug 2 (P18.B1): scala reaching-defs on cats-effect IO.scala flatMap
// must NOT flag function params, `this`, or companion-object names as
// definite-uninitialized.
// ============================================================================

#[test]
fn p18_b1_scala_reaching_defs_no_definite_uninit_for_params_this_objects() {
    let file = "/tmp/repos/scala-cats-effect/core/shared/src/main/scala/cats/effect/IO.scala";
    if !Path::new(file).exists() {
        return;
    }
    let (rc, out) = run_tldr(&["reaching-defs", file, "flatMap", "--format", "json"]);
    assert_eq!(rc, 0, "tldr reaching-defs rc != 0; stdout={}", out);
    let v = parse_json(&out);
    let definite: Vec<&str> = v["uninitialized"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter(|u| u["severity"].as_str() == Some("definite"))
                .filter_map(|u| u["var"].as_str())
                .collect()
        })
        .unwrap_or_default();
    for name in &["f", "this", "IO", "FlatMap", "Tracing"] {
        assert!(
            !definite.iter().any(|d| d == name),
            "scala reaching-defs flatMap must not flag `{}` as definite-uninit; got definite={:?}",
            name,
            definite
        );
    }
}

// ============================================================================
// Bug 3 (P18.R2): swift impact for `_heapify` must report only the real
// definition file (Sources/HeapModule/Heap+UnsafeHandle.swift) and never
// the test file (Tests/HeapTests/HeapTests.swift).
// ============================================================================

#[test]
fn p18_r2_swift_impact_heapify_targets_real_definition_only() {
    let repo = "/tmp/repos/swift-collections";
    if !Path::new(repo).exists() {
        return;
    }
    let (rc, out) = run_tldr(&["impact", "_heapify", repo, "--format", "json"]);
    assert_eq!(rc, 0, "tldr impact rc != 0; stdout={}", out);
    let v = parse_json(&out);
    let files: Vec<String> = v["targets"]
        .as_object()
        .map(|m| {
            m.values()
                .filter_map(|t| t["file"].as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    assert!(
        !files.is_empty(),
        "expected at least one target row for _heapify"
    );
    for f in &files {
        assert!(
            !f.contains("Tests/HeapTests/HeapTests.swift"),
            "swift impact must not fabricate Tests/HeapTests/HeapTests.swift as a definition file for _heapify; targets={:?}",
            files
        );
    }
    assert!(
        files.iter().any(|f| f.contains("Heap+UnsafeHandle.swift")),
        "expected the real Heap+UnsafeHandle.swift to be a target file; got {:?}",
        files
    );
}

// ============================================================================
// Bug 4 (P18.X4): ts-dom-gen `src/` (containing only the `build/` subdir)
// must not be silently empty.
// ============================================================================

#[test]
fn p18_x4_ts_loc_src_with_only_build_subdir_returns_files() {
    let repo = "/tmp/repos/ts-dom-gen";
    if !Path::new(repo).exists() {
        return;
    }
    let (rc, out) = run_tldr(&["loc", &format!("{}/src", repo), "--format", "json"]);
    assert_eq!(rc, 0, "tldr loc rc != 0; stdout={}", out);
    let v = parse_json(&out);
    let total = v["total_files"].as_u64().unwrap_or(0);
    assert!(
        total >= 1,
        "expected at least 1 .ts file under ts-dom-gen/src after the JS/TS preserve fix, got {}",
        total
    );
}

// ============================================================================
// Bug 5 (P18.X1): halstead emits each function exactly once per
// (name, file, line). Pre-fix: java doubled (22 vs 11), elixir nearly
// doubled (299 vs 152).
// ============================================================================

#[test]
fn p18_x1_halstead_java_no_double_emission() {
    let file = "/tmp/repos/spring-petclinic/src/main/java/org/springframework/samples/petclinic/owner/OwnerController.java";
    if !Path::new(file).exists() {
        return;
    }
    let (rc, out) = run_tldr(&["halstead", file, "--format", "json"]);
    assert_eq!(rc, 0, "tldr halstead rc != 0; stdout={}", out);
    let v = parse_json(&out);
    let n = v["functions"].as_array().map(|a| a.len()).unwrap_or(0);
    assert!(
        n <= 12,
        "expected <= 12 java halstead entries (was 22 pre-fix; ground truth 11), got {}",
        n
    );
    assert!(n >= 8, "expected >= 8 entries, got {}", n);
}

#[test]
fn p18_x1_halstead_elixir_no_double_emission() {
    let file = "/tmp/repos/elixir-plug/lib/plug/conn.ex";
    if !Path::new(file).exists() {
        return;
    }
    let (rc, out) = run_tldr(&["halstead", file, "--format", "json"]);
    assert_eq!(rc, 0, "tldr halstead rc != 0; stdout={}", out);
    let v = parse_json(&out);
    let n = v["functions"].as_array().map(|a| a.len()).unwrap_or(0);
    assert!(
        n <= 200,
        "expected <= 200 elixir halstead entries (was 299 pre-fix; ground truth ~152), got {}",
        n
    );
    assert!(n >= 100, "expected >= 100 entries, got {}", n);
}

// ============================================================================
// Bug 6 (P18.Pattern-B): bare + qualified emission collapses to one entry
// across three distinct surfaces.
// ============================================================================

#[test]
fn p18_pattern_b_swift_explain_callees_no_bare_qualified_dup() {
    let file = "/tmp/repos/swift-collections/Sources/HeapModule/Heap+UnsafeHandle.swift";
    if !Path::new(file).exists() {
        return;
    }
    let (rc, out) = run_tldr(&["explain", file, "_heapify", "--format", "json"]);
    assert_eq!(rc, 0, "tldr explain rc != 0; stdout={}", out);
    let v = parse_json(&out);
    let callees = v["callees"].as_array().cloned().unwrap_or_default();
    // Group by line; within a line, no two names should differ only by a
    // qualifier prefix (`x.foo` vs `foo`).
    use std::collections::HashMap;
    let mut by_line: HashMap<u64, Vec<String>> = HashMap::new();
    for c in &callees {
        let line = c["line"].as_u64().unwrap_or(0);
        let name = c["name"].as_str().unwrap_or("").to_string();
        by_line.entry(line).or_default().push(name);
    }
    for (line, names) in &by_line {
        // Compute last-segment for each.
        let mut tails: Vec<&str> = names
            .iter()
            .map(|n| n.rsplit('.').next().unwrap_or(n))
            .collect();
        tails.sort();
        let len = tails.len();
        tails.dedup();
        assert!(
            tails.len() == len,
            "swift explain emitted bare+qualified duplicate at line {}: names={:?}",
            line,
            names
        );
    }
}

#[test]
fn p18_pattern_b_csharp_todo_no_bare_qualified_dup() {
    let file = "/tmp/repos/csharp-newtonsoft-bson-full/Src/Newtonsoft.Json.Bson/Utilities/DateTimeParser.cs";
    if !Path::new(file).exists() {
        return;
    }
    let (rc, out) = run_tldr(&["todo", file, "--format", "json"]);
    assert_eq!(rc, 0, "tldr todo rc != 0; stdout={}", out);
    let v = parse_json(&out);
    let items = v["items"].as_array().cloned().unwrap_or_default();
    // Group by (category, file, line); each group must have <= 1 entry.
    use std::collections::HashMap;
    let mut grouped: HashMap<(String, String, u64), usize> = HashMap::new();
    for it in &items {
        let cat = it["category"].as_str().unwrap_or("").to_string();
        let f = it["file"].as_str().unwrap_or("").to_string();
        let l = it["line"].as_u64().unwrap_or(0);
        *grouped.entry((cat, f, l)).or_insert(0) += 1;
    }
    let dups: Vec<_> = grouped.iter().filter(|(_, &n)| n > 1).collect();
    assert!(
        dups.is_empty(),
        "csharp todo emitted (cat,file,line) duplicates (Pattern-B bare+qualified): {:?}",
        dups
    );
}

#[test]
fn p18_pattern_b_java_structure_constant_not_emitted_as_field() {
    let file = "/tmp/repos/spring-petclinic/src/main/java/org/springframework/samples/petclinic/owner/OwnerController.java";
    if !Path::new(file).exists() {
        return;
    }
    let (rc, out) = run_tldr(&["structure", file, "--format", "json"]);
    assert_eq!(rc, 0, "tldr structure rc != 0; stdout={}", out);
    let v = parse_json(&out);
    // Walk every object that has both name and kind; for any name
    // matching the canonical Java constant, ensure exactly one entry.
    fn walk(node: &serde_json::Value, hits: &mut Vec<(String, String)>) {
        match node {
            serde_json::Value::Object(map) => {
                if let (Some(name), Some(kind)) = (
                    map.get("name").and_then(|x| x.as_str()),
                    map.get("kind").and_then(|x| x.as_str()),
                ) {
                    if name == "VIEWS_OWNER_CREATE_OR_UPDATE_FORM" {
                        hits.push((name.to_string(), kind.to_string()));
                    }
                }
                for v in map.values() {
                    walk(v, hits);
                }
            }
            serde_json::Value::Array(items) => {
                for it in items {
                    walk(it, hits);
                }
            }
            _ => {}
        }
    }
    let mut hits = Vec::new();
    walk(&v, &mut hits);
    assert_eq!(
        hits.len(),
        1,
        "Java `private static final String VIEWS_...` must emit once (was kind:constant + kind:field pre-fix); got {:?}",
        hits
    );
    assert_eq!(
        hits[0].1, "constant",
        "expected kind=constant; got {:?}",
        hits
    );
}

// ============================================================================
// Bug 7 (P18.KOT-3 — already-fixed regression pin): kotlin specs
// --from-tests must populate function_name and at least one spec on
// the canonical InstantTest.kt fixture.
// ============================================================================

#[test]
fn p18_kot_3_kotlin_specs_per_function_emitter_populated() {
    let file = "/tmp/repos/kotlin-datetime/core/common/test/InstantTest.kt";
    if !Path::new(file).exists() {
        return;
    }
    let (rc, out) = run_tldr(&["specs", "--from-tests", file, "--format", "json"]);
    assert_eq!(rc, 0, "tldr specs rc != 0; stdout={}", out);
    let v = parse_json(&out);
    let funcs = v["functions"].as_array().cloned().unwrap_or_default();
    assert!(
        funcs.len() >= 5,
        "expected >= 5 kotlin specs entries, got {}",
        funcs.len()
    );
    let first = &funcs[0];
    assert!(
        first["function_name"].is_string()
            && !first["function_name"].as_str().unwrap_or("").is_empty(),
        "first kotlin specs entry must have a non-empty function_name; got {:?}",
        first
    );
    let total_specs = first["input_output_specs"]
        .as_array()
        .map(|a| a.len())
        .unwrap_or(0)
        + first["exception_specs"]
            .as_array()
            .map(|a| a.len())
            .unwrap_or(0)
        + first["property_specs"]
            .as_array()
            .map(|a| a.len())
            .unwrap_or(0);
    assert!(
        total_specs >= 1,
        "first kotlin specs entry must have at least one spec; got 0"
    );
}

// ============================================================================
// Bug 8 (P18.B8): scala importers must report the actual line of a
// brace-list import, not the synthetic line-1 fallback.
// ============================================================================

#[test]
fn p18_b8_scala_importers_brace_list_line_accuracy() {
    let repo = "/tmp/repos/scala-cats-effect";
    if !Path::new(repo).exists() {
        return;
    }
    let (rc, out) = run_tldr(&[
        "importers",
        "cats.effect.tracing.Tracing",
        repo,
        "--format",
        "json",
    ]);
    assert_eq!(rc, 0, "tldr importers rc != 0; stdout={}", out);
    let v = parse_json(&out);
    let importers = v["importers"].as_array().cloned().unwrap_or_default();
    let io_scala_line: u64 = importers
        .iter()
        .find(|imp| {
            imp["file"]
                .as_str()
                .map(|f| f.ends_with("cats/effect/IO.scala"))
                .unwrap_or(false)
        })
        .and_then(|imp| imp["line"].as_u64())
        .unwrap_or(0);
    assert!(
        io_scala_line >= 50,
        "scala brace-list import in IO.scala must be reported at line >= 50 (actual line is 52); got {}",
        io_scala_line
    );
}

// ============================================================================
// Non-regression assertions
// ============================================================================

// 1. Lua explain m.open still returns 18+ callers (P13.AGG13-12 control).
#[test]
fn p18_nonreg_lua_explain_m_open_still_18_callers() {
    let repo = "/tmp/repos/lua-lsp";
    if !Path::new(repo).exists() {
        return;
    }
    let (rc, out) = run_tldr(&[
        "explain",
        &format!("{}/script/files.lua", repo),
        "m.open",
        "--format",
        "json",
    ]);
    assert_eq!(rc, 0, "tldr explain rc != 0");
    let v = parse_json(&out);
    let n = v["callers"].as_array().map(|a| a.len()).unwrap_or(0);
    assert!(
        n >= 18,
        "non-regression: lua explain m.open must return >= 18 callers (P13.AGG13-12), got {}",
        n
    );
}

// 2. Java reaching-defs (P14.AGG14-12 control): no `owners` definite FP.
#[test]
fn p18_nonreg_java_reaching_defs_no_field_definite_fp() {
    let file = "/tmp/repos/spring-petclinic/src/main/java/org/springframework/samples/petclinic/owner/OwnerController.java";
    if !Path::new(file).exists() {
        return;
    }
    let (rc, out) = run_tldr(&["reaching-defs", file, "processFindForm", "--format", "json"]);
    assert_eq!(rc, 0, "tldr reaching-defs rc != 0");
    let v = parse_json(&out);
    let definite: Vec<&str> = v["uninitialized"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter(|u| u["severity"].as_str() == Some("definite"))
                .filter_map(|u| u["var"].as_str())
                .collect()
        })
        .unwrap_or_default();
    assert!(
        !definite.iter().any(|d| *d == "owners"),
        "non-regression (P14.AGG14-12): java field `owners` must not be definite-uninit; got {:?}",
        definite
    );
}

// 3. Halstead non-regression: rust legitimate per-function emission
//    preserved (each function appears once, no over-dedup).
#[test]
fn p18_nonreg_rust_halstead_per_function_preserved() {
    // Find any rust file in ripgrep that has multiple top-level functions.
    let candidates = [
        "/tmp/repos/ripgrep/crates/core/flags/parse.rs",
        "/tmp/repos/ripgrep/crates/core/flags/hiargs.rs",
        "/tmp/repos/ripgrep/crates/printer/src/standard.rs",
    ];
    let file = match candidates.iter().find(|p| Path::new(p).exists()) {
        Some(p) => *p,
        None => return,
    };
    let (rc, out) = run_tldr(&["halstead", file, "--format", "json"]);
    assert_eq!(rc, 0, "tldr halstead rc != 0");
    let v = parse_json(&out);
    let n = v["functions"].as_array().map(|a| a.len()).unwrap_or(0);
    assert!(
        n >= 1,
        "non-regression: rust halstead must surface >= 1 function on {}, got {}",
        file,
        n
    );
}

// 4. Walker non-regression: node_modules still excluded under
//    auto-JS/TS-preserve.
#[test]
fn p18_nonreg_walker_node_modules_excluded() {
    use std::fs;
    let tmp = std::env::temp_dir().join("p18_nonreg_nm");
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(tmp.join("src/node_modules/foo")).expect("mkdir");
    fs::write(tmp.join("src/index.ts"), "export const x = 1;\n").expect("write");
    fs::write(
        tmp.join("src/node_modules/foo/index.js"),
        "module.exports = 1;\n",
    )
    .expect("write");
    let (rc, out) = run_tldr(&["loc", tmp.join("src").to_str().unwrap(), "--format", "json"]);
    assert_eq!(rc, 0, "tldr loc rc != 0");
    let v = parse_json(&out);
    let n = v["total_files"].as_u64().unwrap_or(0);
    assert_eq!(
        n, 1,
        "non-regression: node_modules must remain excluded; expected 1 (just src/index.ts), got {}",
        n
    );
    let _ = fs::remove_dir_all(&tmp);
}

// 5. Rust loc non-regression: ripgrep crates layout still works.
#[test]
fn p18_nonreg_rust_loc_ripgrep_crates() {
    let path = "/tmp/repos/ripgrep/crates";
    if !Path::new(path).exists() {
        return;
    }
    let (rc, out) = run_tldr(&["loc", path, "--format", "json"]);
    assert_eq!(rc, 0, "tldr loc rc != 0");
    let v = parse_json(&out);
    let n = v["total_files"].as_u64().unwrap_or(0);
    assert!(
        n >= 50,
        "non-regression: rust loc on ripgrep/crates must surface >= 50 files, got {}",
        n
    );
}

// 6. Java importers non-regression (P15.AGG15-3 control).
#[test]
fn p18_nonreg_java_importers_owner() {
    let repo = "/tmp/repos/spring-petclinic";
    if !Path::new(repo).exists() {
        return;
    }
    let (rc, out) = run_tldr(&["importers", "Owner", repo, "--format", "json"]);
    assert_eq!(rc, 0, "tldr importers rc != 0");
    let v = parse_json(&out);
    let total = v["total"].as_u64().unwrap_or(0);
    assert!(
        total >= 1,
        "non-regression: java importers `Owner` must return >= 1 (P15.AGG15-3), got {}",
        total
    );
}

// 7. Go specs non-regression: --from-tests still populates function_name.
#[test]
fn p18_nonreg_go_specs_from_tests() {
    let file = "/tmp/repos/go-httprouter/tree_test.go";
    if !Path::new(file).exists() {
        return;
    }
    let (rc, out) = run_tldr(&["specs", "--from-tests", file, "--format", "json"]);
    assert_eq!(rc, 0, "tldr specs rc != 0");
    let v = parse_json(&out);
    let funcs = v["functions"].as_array().cloned().unwrap_or_default();
    assert!(
        !funcs.is_empty(),
        "non-regression: go specs --from-tests must surface >= 1 function"
    );
    let first = &funcs[0];
    assert!(
        first["function_name"].is_string()
            && !first["function_name"].as_str().unwrap_or("").is_empty(),
        "non-regression: go specs first function must have non-empty function_name"
    );
}
