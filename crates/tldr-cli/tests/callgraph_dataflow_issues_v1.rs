//! callgraph-dataflow-issues-v1 (v0.4.2 M-107)
//!
//! Regression tests for four call-graph + dataflow defects surfaced by
//! Phase-22 iter-2 audit reports:
//!
//!   * Issue #39 — Python decorator-arg callbacks miss CALL edges
//!     (`crates/tldr-core/src/callgraph/languages/python.rs:465-490`)
//!   * Issue #50 — SSA taint misses self-assignment / RHS-uses propagation
//!     (`crates/tldr-core/src/security/taint.rs` SSA sink check)
//!   * Issue #54 — Cross-file same-named inheritance node collision
//!     (`crates/tldr-core/src/inheritance/mod.rs` + `types/inheritance.rs`)
//!   * Issue #60 — Go single-letter receiver misresolution
//!     (`crates/tldr-core/src/callgraph/type_resolver.rs:643-644` +
//!     `crates/tldr-core/src/callgraph/resolution.rs:327-329`)
//!
//! Each test asserts the post-fix invariant; pre-fix all four are RED.

use std::fs;
use tempfile::TempDir;

use tldr_core::callgraph::build_project_call_graph;
use tldr_core::inheritance::{extract_inheritance, InheritanceOptions};
use tldr_core::security::taint::compute_taint_with_tree;
use tldr_core::types::Language;

// =============================================================================
// Issue #39 — Python decorator-arg callbacks should produce CALL edges
// =============================================================================
//
// `@register(my_handler)` invokes `register(my_handler)` at decoration time
// and the identifier `my_handler` is a top-level reference to a known
// function. The call-graph builder previously walked the decorator subtree
// only for nested `call` nodes; identifier arguments inside the call's
// `argument_list` were never emitted as ref/CALL edges. Result: `tldr
// impact my_handler .` reported `caller_count: 0` despite the decorator
// reference being plainly present in the source.

#[test]
fn issue_39_python_decorator_arg_callback_creates_edge() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();

    let src = r#""""Decorator-arg callback fixture for #39."""

def my_handler():
    return "handled"

def my_validator():
    return True

def register(callback):
    def wrapper(func):
        return func
    return wrapper

@register(my_handler)
def decorated_func():
    return None

@register(my_handler, my_validator)
def multi_decorated():
    return None
"#;
    fs::write(root.join("decorator_callback.py"), src).unwrap();

    let graph = build_project_call_graph(root, Language::Python, None, true)
        .expect("build_project_call_graph ok");

    let all_edges: Vec<_> = graph.edges().collect();
    let edges_to_my_handler: Vec<_> = all_edges
        .iter()
        .filter(|e| e.dst_func == "my_handler")
        .copied()
        .collect();

    assert!(
        !edges_to_my_handler.is_empty(),
        "Expected at least one CALL edge into my_handler from decorator args; got 0.\n\
         All edges: {:?}",
        all_edges
    );

    // The decorated function names are the natural source of these edges
    // (caller_name is set to the decorated function in python.rs:445-461).
    let callers: std::collections::HashSet<&str> = edges_to_my_handler
        .iter()
        .map(|e| e.src_func.as_str())
        .collect();
    let has_decorated = callers.contains("decorated_func") || callers.contains("multi_decorated");
    assert!(
        has_decorated,
        "Expected decorated_func or multi_decorated to be source of my_handler ref edge; \
         saw callers: {:?}",
        callers
    );
}

#[test]
fn issue_39_python_decorator_arg_multi_callbacks_all_emit() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();

    let src = r#"def alpha():
    return 1

def beta():
    return 2

def register(*cbs):
    def wrap(func):
        return func
    return wrap

@register(alpha, beta)
def f():
    return None
"#;
    fs::write(root.join("multi.py"), src).unwrap();

    let graph = build_project_call_graph(root, Language::Python, None, true)
        .expect("graph ok");

    let dsts: std::collections::HashSet<String> =
        graph.edges().map(|e| e.dst_func.clone()).collect();

    assert!(
        dsts.contains("alpha"),
        "alpha should appear as a callee of decorator-arg ref; saw: {:?}",
        dsts
    );
    assert!(
        dsts.contains("beta"),
        "beta should appear as a callee of decorator-arg ref; saw: {:?}",
        dsts
    );
}

// =============================================================================
// Issue #50 — SSA self-assignment / RHS-uses propagation
// =============================================================================
//
// Fixture mirrors `/tmp/audit_phase22/js/selfasn.js`. The chain
//   let user_input = process.env.INPUT;  // env_var source
//   x = user_input;                       // SSA def of x, uses user_input
//   eval(x);                              // code_eval sink
// must produce `sink.tainted == true` and at least one flow. Pre-fix the
// SSA sink check could only inspect SSA `inst.uses` at the sink line —
// but `eval(x)` produces no SSA instruction (no LHS def), so the check
// returned false and the M1a indirect-match fallback was suppressed
// because `x` IS SSA-tracked.

fn run_taint(source: &str, function: &str, language: Language) -> tldr_core::TaintInfo {
    use tldr_core::ast::parser::parse;
    use tldr_core::cfg::get_cfg_context;
    use tldr_core::dfg::get_dfg_context;
    use tldr_core::ssa::{construct_ssa, SsaType};

    let cfg = get_cfg_context(source, function, language).expect("cfg ok");
    let dfg = get_dfg_context(source, function, language).expect("dfg ok");
    let tree = parse(source, language).expect("parse ok");

    // Build per-line statements map.
    let mut statements: std::collections::HashMap<u32, String> = std::collections::HashMap::new();
    for (idx, line) in source.lines().enumerate() {
        statements.insert((idx as u32) + 1, line.to_string());
    }

    let refs: Vec<tldr_core::types::VarRef> = dfg.refs.clone();
    let ssa = construct_ssa(source, function, language, SsaType::SemiPruned).ok();

    compute_taint_with_tree(
        &cfg,
        &refs,
        &statements,
        Some(&tree),
        Some(source.as_bytes()),
        language,
        ssa.as_ref(),
    )
    .expect("taint ok")
}

#[test]
fn issue_50_ssa_self_assign_propagates_taint_to_sink() {
    let src = r#"function selfish() {
  let x = 1;
  x = x + 1;
  let user_input = process.env.INPUT;
  x = user_input;
  eval(x);
  return x;
}
"#;
    let info = run_taint(src, "selfish", Language::JavaScript);

    assert!(
        !info.sources.is_empty(),
        "source user_input must be detected; sources: {:?}",
        info.sources
    );

    let tainted_sinks: Vec<_> = info.sinks.iter().filter(|s| s.tainted).collect();
    assert!(
        !tainted_sinks.is_empty(),
        "eval(x) sink must be marked tainted under SSA propagation of x = user_input. \
         sinks: {:?}, flows: {:?}",
        info.sinks,
        info.flows
    );

    assert!(
        !info.flows.is_empty(),
        "At least one flow user_input -> eval(x) expected; flows: {:?}",
        info.flows
    );
}

#[test]
fn issue_50_ssa_await_propagates_taint_to_sink() {
    let src = r#"async function handler(req) {
  const input = req.body.input;
  const result = await processInput(input);
  eval(result);
  return result;
}
"#;
    let info = run_taint(src, "handler", Language::JavaScript);

    let tainted_sinks: Vec<_> = info.sinks.iter().filter(|s| s.tainted).collect();
    assert!(
        !tainted_sinks.is_empty(),
        "eval(result) sink must be tainted via input -> await processInput(input) -> result. \
         sinks: {:?}",
        info.sinks
    );
}

// =============================================================================
// Issue #54 — Cross-file same-named inheritance nodes must not collide
// =============================================================================
//
// Two files each declare a class `Foo` with different parents. The
// inheritance graph keyed nodes by bare name only, so the second file's
// `Foo` silently overwrote the first. Post-fix the report must preserve
// BOTH `Foo` entries (one per file) and BOTH parent edges must appear with
// correct child_file metadata.

#[test]
fn issue_54_cross_file_same_named_class_preserved_cpp() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();

    let a = r#"class Base { };
class Foo : public Base {
public:
    int x;
};
"#;
    let b = r#"class Mixer { };
class Foo : public Mixer {
public:
    int y;
};
"#;
    fs::write(root.join("a.cpp"), a).unwrap();
    fs::write(root.join("b.cpp"), b).unwrap();

    let report = extract_inheritance(root, Some(Language::Cpp), &InheritanceOptions::default())
        .expect("inheritance ok");

    // Both edges must appear: Foo->Base (from a.cpp) and Foo->Mixer (from b.cpp).
    let mut parents_of_foo: Vec<&str> = report
        .edges
        .iter()
        .filter(|e| e.child == "Foo")
        .map(|e| e.parent.as_str())
        .collect();
    parents_of_foo.sort();
    parents_of_foo.dedup();

    assert!(
        parents_of_foo.contains(&"Base"),
        "Foo->Base edge (from a.cpp) must be present; edges: {:?}",
        report.edges
    );
    assert!(
        parents_of_foo.contains(&"Mixer"),
        "Foo->Mixer edge (from b.cpp) must be present; edges: {:?}",
        report.edges
    );

    // Each Foo edge must be attributed to the correct child file.
    let foo_base_edge = report
        .edges
        .iter()
        .find(|e| e.child == "Foo" && e.parent == "Base")
        .expect("Foo->Base edge present");
    assert!(
        foo_base_edge.child_file.ends_with("a.cpp"),
        "Foo->Base child_file must be a.cpp; got: {:?}",
        foo_base_edge.child_file
    );

    let foo_mixer_edge = report
        .edges
        .iter()
        .find(|e| e.child == "Foo" && e.parent == "Mixer")
        .expect("Foo->Mixer edge present");
    assert!(
        foo_mixer_edge.child_file.ends_with("b.cpp"),
        "Foo->Mixer child_file must be b.cpp; got: {:?}",
        foo_mixer_edge.child_file
    );
}

#[test]
fn issue_54_cross_file_same_named_class_preserved_python() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();

    let a = r#"class Base:
    pass

class Widget(Base):
    pass
"#;
    let b = r#"class Mixer:
    pass

class Widget(Mixer):
    pass
"#;
    fs::write(root.join("a.py"), a).unwrap();
    fs::write(root.join("b.py"), b).unwrap();

    let report = extract_inheritance(root, Some(Language::Python), &InheritanceOptions::default())
        .expect("inheritance ok");

    let parents: std::collections::HashSet<&str> = report
        .edges
        .iter()
        .filter(|e| e.child == "Widget")
        .map(|e| e.parent.as_str())
        .collect();

    assert!(
        parents.contains("Base"),
        "Widget->Base edge from a.py expected; edges: {:?}",
        report.edges
    );
    assert!(
        parents.contains("Mixer"),
        "Widget->Mixer edge from b.py expected; edges: {:?}",
        report.edges
    );
}

// =============================================================================
// Issue #60 — Go single-letter receiver inside another method must use
// var_types lookup, not shortcut to enclosing receiver type.
// =============================================================================
//
// Pre-fix `c.Meow()` inside `func (d Dog) Process()` resolved `c` as
// receiver type `Dog` because the resolver shortcut to High confidence
// whenever the receiver name was a single letter — even when a local
// `c := Cat{}` binding existed. The post-fix resolver consults
// `find_go_struct_literal` first and only falls back to the enclosing
// receiver when no local binding exists.

#[test]
fn issue_60_go_single_letter_local_var_resolves_to_local_type() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();

    let src = r#"package fixture

type Cat struct{}

func (c Cat) Meow() string { return "meow" }

type Dog struct{}

func (d Dog) Bark() string { return "bark" }

func (d Dog) Process() string {
	c := Cat{}
	return c.Meow() + d.Bark()
}
"#;
    fs::write(root.join("animals.go"), src).unwrap();

    let graph = build_project_call_graph(root, Language::Go, None, true).expect("graph ok");

    let edges: Vec<_> = graph.edges().collect();
    let process_callees: Vec<&str> = edges
        .iter()
        .filter(|e| {
            e.src_func == "Dog.Process"
                || e.src_func == "Process"
                || e.src_func.ends_with(".Process")
        })
        .map(|e| e.dst_func.as_str())
        .collect();

    assert!(
        process_callees
            .iter()
            .any(|f| *f == "Cat.Meow" || *f == "Meow"),
        "Process must call Cat.Meow (via local c := Cat{{}}). callees seen: {:?}",
        process_callees
    );
    assert!(
        process_callees
            .iter()
            .any(|f| *f == "Dog.Bark" || *f == "Bark"),
        "Process must call Dog.Bark (via enclosing receiver d). callees seen: {:?}",
        process_callees
    );
}

#[test]
fn issue_60_go_pointer_struct_literal_local_resolves() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();

    let src = r#"package fixture

type Service struct{}

func (s *Service) DoWork() {}

type Driver struct{}

func (d *Driver) Run() {
	s := &Service{}
	s.DoWork()
}
"#;
    fs::write(root.join("pointer.go"), src).unwrap();

    let graph = build_project_call_graph(root, Language::Go, None, true).expect("graph ok");

    let dst_funcs: std::collections::HashSet<String> = graph
        .edges()
        .filter(|e| e.src_func.contains("Run"))
        .map(|e| e.dst_func.clone())
        .collect();

    assert!(
        dst_funcs
            .iter()
            .any(|f| f == "Service.DoWork" || f == "DoWork"),
        "Run must call Service.DoWork via s := &Service{{}}; saw: {:?}",
        dst_funcs
    );
}
