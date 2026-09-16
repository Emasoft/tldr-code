//! language-adapters-completeness-v1 — regression suite for four
//! Phase-12 audit findings (P12.AGG12-4, AGG12-7, AGG12-8, AGG12-9)
//! that exposed gaps in language-adapter coverage of CommonJS-style JS,
//! OCaml functor bodies, OCaml module-wrapper interface naming, and
//! Elixir mix-project deps + PDG slicing.
//!
//! Each test is gated on the presence of an upstream sample under
//! `/tmp/repos/<name>`. Where the fixture is missing the test exits
//! early with `return` — there is no `cfg` skip, so CI runs them
//! whenever the corpora are present (no-op otherwise).
//!
//! These tests follow the no-synthetic-fixtures-v1 architecture: every
//! assertion runs against a real upstream repository, never a
//! TempDir-with-inline-source fixture. Synthetic fixtures hide the
//! exact AST shapes (functor parameters, multi-clause defs, `app.method
//! = function name() {}`) the bugs depend on.

use assert_cmd::Command;
use serde_json::Value;
use std::path::Path;

fn run_tldr_json(args: &[&str]) -> Option<Value> {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("tldr"));
    cmd.args(args).arg("--format").arg("json");
    let output = cmd.output().expect("failed to execute tldr");
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    serde_json::from_str(&stdout).ok()
}

fn require_repo(path: &str) -> bool {
    Path::new(path).exists()
}

// =============================================================================
// BUG-AGG12-4: OCaml call graph severely under-resolves let-bindings inside
//              functor bodies (`module Make (V) = struct ... end`).
// =============================================================================

/// dune's `src/dag/dag.ml` wraps every helper in a `module Make (Value)
/// () : S with type value := Value.t = struct ... end` functor. Phase
/// 12 reported `tldr calls /tmp/repos/ocaml-dune/src/dag` returning
/// nodes=2 even though `tldr structure` enumerates 24 functions in the
/// same file. The fix: include every defined function as a node in the
/// call-graph output, not only ones that participate in resolved edges.
#[test]
fn test_calls_ocaml_functor_body_resolved() {
    let repo = "/tmp/repos/ocaml-dune/src/dag";
    if !require_repo(repo) {
        return;
    }

    let v = run_tldr_json(&["calls", repo]).expect("calls JSON");
    let nodes = v
        .get("nodes")
        .and_then(Value::as_array)
        .expect("calls.nodes array present");
    assert!(
        nodes.len() >= 10,
        "ocaml functor body callgraph should expose at least 10 nodes; \
         got {} on {}: {:?}",
        nodes.len(),
        repo,
        nodes,
    );
}

/// Multi-language consistency: callgraph node count for a given file
/// must agree with `tldr structure` function count. Pre-fix dag.ml
/// reported nodes=2 vs structure_funcs=24 — the call graph was lying
/// about which functions exist.
#[test]
fn test_calls_ocaml_functor_baseline_consistent() {
    let dir = "/tmp/repos/ocaml-dune/src/dag";
    let file = "/tmp/repos/ocaml-dune/src/dag/dag.ml";
    if !require_repo(dir) || !Path::new(file).exists() {
        return;
    }

    let calls = run_tldr_json(&["calls", dir]).expect("calls JSON");
    let calls_nodes = calls
        .get("nodes")
        .and_then(Value::as_array)
        .map(|a| a.len())
        .unwrap_or(0);

    let structure = run_tldr_json(&["structure", file]).expect("structure JSON");
    let structure_fns = structure
        .get("files")
        .and_then(Value::as_array)
        .and_then(|files| files.first())
        .and_then(|f| f.get("definitions"))
        .and_then(Value::as_array)
        .map(|defs| {
            defs.iter()
                .filter(|d| d.get("kind").and_then(Value::as_str) == Some("function"))
                .count()
        })
        .unwrap_or(0);

    assert!(
        structure_fns > 0,
        "structure must report at least one function for {}",
        file,
    );
    assert!(
        calls_nodes >= structure_fns,
        "calls.nodes ({}) should cover every structure-defined function ({}) \
         on {} — pre-fix dag.ml reported 2 nodes for 24 structure functions",
        calls_nodes,
        structure_fns,
        file,
    );
}

// =============================================================================
// BUG-AGG12-7: JS CommonJS `obj.method = function name()` pattern defeats
//              call-graph resolution.
// =============================================================================

/// Express ships every method as `app.method = function name() { ... }`.
/// `lib/express.js:54` calls `app.init()`, where `app.init` is defined
/// in `lib/application.js:59` via the CommonJS pattern. Phase-12
/// `tldr impact init /tmp/repos/express` reported zero callers because
/// the TS handler's `extract_definitions` skipped
/// `assignment_expression > function_expression` and the resolver's
/// global fuzzy fallback rejected non-method funcs.
#[test]
fn test_impact_js_commonjs_method_assignment() {
    let repo = "/tmp/repos/express";
    if !require_repo(repo) {
        return;
    }

    // Try several known CommonJS methods; assert at least one returns
    // ≥1 caller. Single-method assertions are brittle to upstream
    // refactors that might rename a single call site.
    let candidates = ["init", "defaultConfiguration", "handle", "render"];
    let mut total_callers = 0usize;
    for method in candidates {
        let v = match run_tldr_json(&["impact", method, repo]) {
            Some(v) => v,
            None => continue,
        };
        let targets = v.get("targets").and_then(Value::as_object);
        if let Some(map) = targets {
            for (_, t) in map {
                if let Some(callers) = t.get("callers").and_then(Value::as_array) {
                    total_callers += callers.len();
                }
            }
        }
    }
    assert!(
        total_callers >= 1,
        "Express CommonJS methods should have at least 1 caller across {:?}; \
         got total={} (pre-fix: 0 for all methods)",
        candidates,
        total_callers,
    );
}

/// Cross-command consistency: `tldr explain` on the same target
/// should also see the CommonJS callers populate. Both `impact` and
/// `explain` feed off the same call-graph IR; a divergence means one
/// path failed to recognize a CommonJS-method definition.
#[test]
fn test_explain_js_commonjs_callers() {
    let app_file = "/tmp/repos/express/lib/application.js";
    if !Path::new(app_file).exists() {
        return;
    }

    // `tldr explain <file> <function>` analyses one specific file.
    // Pick a method that we know has at least one caller post-fix
    // (`init` is called by createApplication in lib/express.js:54).
    // The explain output exposes callers in `change_impact.callers`
    // (or similar); we just need to confirm the JSON shape is sane and
    // that callers is populated for at least one CommonJS method when
    // explain runs over the project surface.
    let methods = ["init", "defaultConfiguration", "handle", "render"];
    let mut found_caller = false;
    for method in methods {
        let v = match run_tldr_json(&["explain", app_file, method]) {
            Some(v) => v,
            None => continue,
        };
        // explain's caller info lives under change_impact (V2) or
        // callers (V1) — accept either.
        let caller_count = v
            .get("change_impact")
            .and_then(|ci| ci.get("callers"))
            .and_then(Value::as_array)
            .map(|a| a.len())
            .or_else(|| v.get("callers").and_then(Value::as_array).map(|a| a.len()))
            .unwrap_or(0);
        if caller_count > 0 {
            found_caller = true;
            break;
        }
    }
    assert!(
        found_caller,
        "tldr explain on lib/application.js must report ≥1 caller for at \
         least one of {:?} — BUG-AGG12-7 cross-command regression check",
        methods,
    );
}

// =============================================================================
// BUG-AGG12-8: Elixir `deps` reports 0 internal dependencies; slice
//              returns 0 lines for known function bodies.
// =============================================================================

/// Plug uses `alias`, `import`, `use`, and `require` extensively.
/// Phase-12 reported `tldr deps /tmp/repos/elixir-plug/lib` returning
/// `total_internal_deps: 0` because `index_elixir_module` only emitted
/// the canonical `Plug.Conn` module name when the relative path began
/// with `lib/` or `test/` — and `tldr deps lib` strips that prefix.
#[test]
fn test_deps_elixir_resolves_alias() {
    let repo = "/tmp/repos/elixir-plug/lib";
    if !require_repo(repo) {
        return;
    }

    let v = run_tldr_json(&["deps", repo]).expect("deps JSON");
    let total = v
        .get("stats")
        .and_then(|s| s.get("total_internal_deps"))
        .and_then(Value::as_u64)
        .expect("deps.stats.total_internal_deps present");
    assert!(
        total >= 10,
        "elixir alias resolution should produce ≥10 internal deps for plug/lib; \
         got {} (pre-fix: 0)",
        total,
    );
}

/// Slice on a single-clause Elixir function body must return at least
/// the criterion line plus its dependents. `Plug.Conn.assign/3` at
/// line 316 is a one-line-body pipeline that exercises the elixir DFG
/// extractor's `match_operator` recognition.
#[test]
fn test_slice_elixir_returns_lines() {
    let file = "/tmp/repos/elixir-plug/lib/plug/conn.ex";
    if !Path::new(file).exists() {
        return;
    }

    let v = run_tldr_json(&["slice", file, "assign", "316"]).expect("slice JSON");
    let line_count = v
        .get("line_count")
        .and_then(Value::as_u64)
        .expect("slice.line_count present");
    assert!(
        line_count >= 1,
        "elixir slice on assign/316 should return at least 1 line; got {}",
        line_count,
    );
}

// =============================================================================
// BUG-AGG12-9: OCaml interface emits empty class name for
//              module/functor wrapper.
// =============================================================================

/// dune's `dag.ml` wraps everything in `module Make (V) = struct ...
/// end`. Phase-12 reported `interface.classes[0].name = ""` because
/// P11's BUG-AGG-8 fix only touched `value_definition` / `let_binding`,
/// missing the `module_definition > module_binding > module_name` path.
#[test]
fn test_interface_ocaml_module_name_populated() {
    let file = "/tmp/repos/ocaml-dune/src/dag/dag.ml";
    if !Path::new(file).exists() {
        return;
    }

    let v = run_tldr_json(&["interface", file]).expect("interface JSON");
    let classes = v
        .get("classes")
        .and_then(Value::as_array)
        .expect("interface.classes array present");
    assert!(
        !classes.is_empty(),
        "interface must report at least one class for dag.ml",
    );
    let first_name = classes[0]
        .get("name")
        .and_then(Value::as_str)
        .expect("classes[0].name present");
    assert!(
        !first_name.is_empty(),
        "OCaml functor module wrapper class name must be non-empty for dag.ml; \
         pre-fix Phase-12 reported \"\". Got \"{}\"",
        first_name,
    );
    // The functor in dag.ml is named `Make` — assert that exact value
    // for a strong consistency signal.
    assert_eq!(
        first_name, "Make",
        "expected dag.ml module wrapper class name to be `Make`; got `{}`",
        first_name,
    );
}

/// Regression check: P11's `io_buffer.ml` fix must still hold. The
/// file's synthetic class is a `type_definition` (`type t = { ... }`),
/// which P11 fixed via the `value_definition` / `let_binding` branch.
/// Our BUG-AGG12-9 fix added handling for `module_definition` and
/// `type_definition`; verify io_buffer.ml continues to populate a
/// non-empty class name.
#[test]
fn test_interface_ocaml_io_buffer_unchanged() {
    let file = "/tmp/repos/ocaml-dune/src/rpc/io_buffer.ml";
    if !Path::new(file).exists() {
        return;
    }

    let v = run_tldr_json(&["interface", file]).expect("interface JSON");
    let classes = v
        .get("classes")
        .and_then(Value::as_array)
        .expect("interface.classes array present");
    assert!(
        !classes.is_empty(),
        "io_buffer.ml must report at least one class (P11 regression check)",
    );
    let first_name = classes[0]
        .get("name")
        .and_then(Value::as_str)
        .expect("classes[0].name present");
    assert!(
        !first_name.is_empty(),
        "io_buffer.ml first class name must be non-empty (P11 BUG-AGG-8 \
         regression check); got \"{}\"",
        first_name,
    );
}
