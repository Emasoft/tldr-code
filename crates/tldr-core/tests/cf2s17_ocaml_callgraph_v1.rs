//! CF2-S17 — OCaml call-graph consistency (calls / impact / explain).
//!
//! Generalization gate for the OCaml call-graph symptom class. Two AST-driven
//! defects in the OCaml call-edge builder are pinned here:
//!
//!   1. `let f = function ...` / `let f = fun x -> ...` bindings are *named
//!      functions* whose parameters hang off the lambda, not the `let_binding`.
//!      The builder treated them as bodyless value bindings and siphoned every
//!      call in the body into the `<module>` pseudo-node, leaving the real
//!      function `f` reporting `callees = 0`.
//!
//!   2. A call to a same-file definition written with its fully-qualified
//!      module path (`Outer.Sub.target`) was emitted as an unresolved `Attr`
//!      call instead of being collapsed to the bare local definition
//!      (`target`). `impact target` therefore reported `caller_count = 0` for
//!      those qualified call sites even though `explain target` resolved them.
//!
//! Both assertions FAIL on the pre-fix source and PASS afterwards. The test
//! operates directly on `OcamlHandler::extract_calls` — the exact map the
//! cross-file builder, `impact`, and `explain` all consume.

use std::collections::BTreeSet;
use std::path::Path;

use tldr_core::ast::parser::parse;
use tldr_core::callgraph::cross_file_types::CallType;
use tldr_core::callgraph::languages::ocaml::OcamlHandler;
use tldr_core::callgraph::languages::CallGraphLanguageSupport;
use tldr_core::Language;

fn extract_calls(src: &str) -> std::collections::HashMap<String, Vec<tldr_core::callgraph::cross_file_types::CallSite>> {
    let handler = OcamlHandler::new();
    let tree = parse(src, Language::Ocaml).expect("ocaml source parses");
    handler
        .extract_calls(Path::new("t.ml"), src, &tree)
        .expect("extract_calls succeeds")
}

/// (a) A function defined via `function` / `fun` (and one whose calls live in a
/// nested `let ... in`) must report its callees against the *enclosing named
/// function*, never the `<module>` pseudo-node.
#[test]
fn lambda_and_nested_let_calls_attribute_to_enclosing_function() {
    let src = "let helper x = x + 1\n\
               let dispatch = function\n  | 0 -> helper 0\n  | n -> helper (helper n)\n\
               let lam = fun y -> helper y\n\
               let outer p =\n  let inner = helper p in\n  inner\n";
    let calls = extract_calls(src);

    // `let dispatch = function ...` — dispatch owns the helper calls.
    let dispatch = calls
        .get("dispatch")
        .expect("dispatch (let = function) must report its callees, not <module>");
    assert!(
        dispatch.iter().any(|c| c.target == "helper"),
        "dispatch must call helper; got {:?}",
        dispatch.iter().map(|c| &c.target).collect::<Vec<_>>()
    );

    // `let lam = fun y -> ...` — lam owns the helper call.
    let lam = calls
        .get("lam")
        .expect("lam (let = fun) must report its callees, not <module>");
    assert!(
        lam.iter().any(|c| c.target == "helper"),
        "lam must call helper; got {:?}",
        lam.iter().map(|c| &c.target).collect::<Vec<_>>()
    );

    // The lambda bodies must NOT have leaked into the module pseudo-node.
    if let Some(module_calls) = calls.get("<module>") {
        assert!(
            !module_calls.iter().any(|c| c.target == "helper"),
            "lambda/function bodies must not be siphoned into <module>; got {:?}",
            module_calls.iter().map(|c| &c.target).collect::<Vec<_>>()
        );
    }

    // Nested `let inner = helper p in ...` rolls up to the enclosing `outer`;
    // `inner` must never surface as its own caller key in the handler output.
    let outer = calls
        .get("outer")
        .expect("outer must report the nested-let call");
    assert!(
        outer.iter().any(|c| c.target == "helper"),
        "outer must call helper (through its nested let); got {:?}",
        outer.iter().map(|c| &c.target).collect::<Vec<_>>()
    );
    assert!(
        !calls.contains_key("inner"),
        "nested let-binding `inner` must not become a separate caller node"
    );
}

/// (b) A same-file definition reached through its full module path
/// (`Outer.Sub.target`) must collapse to the bare local definition so the
/// reverse call graph (`impact`) counts every qualified caller — matching the
/// caller set `explain` resolves.
#[test]
fn qualified_same_file_call_sites_map_to_bare_definition() {
    let src = "module Outer = struct\n  module Sub = struct\n    let target x = x + 1\n\
               \n    let helper2 = function\n      | 0 -> target 0\n      | n -> target n\n  end\nend\n\
               let c1 z = Outer.Sub.target z\n\
               let c2 w = Outer.Sub.target (Outer.Sub.target w)\n\
               let c3 a = Outer.Sub.target a\n";
    let calls = extract_calls(src);

    // No call site may retain the fully-qualified spelling of a local def.
    for (caller, sites) in &calls {
        for s in sites {
            assert_ne!(
                s.target, "Outer.Sub.target",
                "qualified local call from `{caller}` must collapse to bare `target`"
            );
        }
    }

    // Distinct caller functions of the bare local `target` — this is exactly
    // what `impact target` counts and what `explain target` lists.
    let mut callers_of_target: BTreeSet<String> = BTreeSet::new();
    for (caller, sites) in &calls {
        if sites
            .iter()
            .any(|s| s.target == "target" && s.call_type == CallType::Intra)
        {
            // Module-qualified duplicate keys (`Outer.Sub.helper2`) and the
            // bare key refer to the same function — normalise to the bare name.
            let bare = caller.rsplit('.').next().unwrap_or(caller).to_string();
            callers_of_target.insert(bare);
        }
    }

    for expected in ["helper2", "c1", "c2", "c3"] {
        assert!(
            callers_of_target.contains(expected),
            "impact: `{expected}` must be counted as a caller of `target`; got {callers_of_target:?}"
        );
    }
    assert_eq!(
        callers_of_target.len(),
        4,
        "impact must report exactly 4 distinct callers of `target`; got {callers_of_target:?}"
    );
}
