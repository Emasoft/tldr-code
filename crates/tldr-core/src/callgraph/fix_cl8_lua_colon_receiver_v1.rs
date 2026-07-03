//! fix-cl-8-v1 (BUG-5, LUA colon-receiver): real-parse regression pins for the
//! Lua `self:method()` sibling mis-bind fix.
//!
//! Background (luvit `deps/http.lua`): `ClientRequest:_done` — a `Writable`
//! subclass that does NOT itself define `_end` — calls `self:_end()`. The same
//! file also defines the UNRELATED `ServerResponse:_end`. The greedy same-file
//! self-dispatch used to bind the wrong `ServerResponse:_end` sibling.
//!
//! The Lua frontend deliberately does NOT set `class_name`/`is_method` on a
//! colon method (`function T:m`) — doing so makes `resolve_caller_name` relabel
//! every colon-method-sourced edge `m` -> `T.m`, a catastrophic 700+-edge flip
//! that was reverted twice. Instead, colon methods carry a
//! `resolve_caller_name`-INVISIBLE `colon_receiver = Some("T")` field (mirroring
//! `is_lexical_local`). The BUG-5 guard reads `colon_receiver` to derive both the
//! enclosing class and the same-file candidate's class, so it can DECLINE the
//! unrelated-sibling bind — while every genuine own/ancestor dispatch and every
//! non-Lua language stays byte-for-byte unchanged.

use crate::callgraph::builder_v2::{build_project_call_graph_v2, BuildConfig};
use std::path::Path;

fn build_lua_graph(dir: &Path) -> crate::callgraph::cross_file_types::CallGraphIR {
    let config = BuildConfig {
        language: "lua".to_string(),
        use_type_resolution: true,
        ..Default::default()
    };
    build_project_call_graph_v2(dir, config).expect("build lua call graph")
}

/// DECLINE: `A:done` calls `self:go()`; `A` does NOT define `go`; `go` is defined
/// only by the two UNRELATED same-file siblings `B:go` and `C:go`. Because the
/// `self` receiver is typed `A` (via `colon_receiver`) and neither `A` nor any
/// ancestor owns `go`, and `go` has >= 2 unrelated definers (so declining does
/// not drop a UNIQUE name-match — the never-worse invariant), the guard DECLINES:
/// no `done -> go` edge is emitted rather than binding the wrong sibling.
///
/// Two unrelated definers reproduce the real luvit cardinality (`ServerResponse:
/// _end` sibling + cross-file `Writable:_end` ancestor). Lua carries no class
/// index, so the guard cannot climb to a would-be ancestor; the `>= 2` gate is
/// exactly what keeps a single (likely-correct, unique) definer bound.
#[test]
fn lua_self_colon_unrelated_sibling_is_declined() {
    let dir = std::env::temp_dir().join(format!("tldr_cl8_lua_decline_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");

    // A:done -> self:go(); A has no `go`. `go` lives only on unrelated B and C.
    std::fs::write(
        dir.join("mod.lua"),
        "function A:done()\n\
         \x20   self:go()\n\
         end\n\
         \n\
         function B:go()\n\
         \x20   return 1\n\
         end\n\
         \n\
         function C:go()\n\
         \x20   return 2\n\
         end\n",
    )
    .unwrap();

    let graph = build_lua_graph(&dir);

    let done_to_go: Vec<_> = graph
        .edges()
        .iter()
        .filter(|e| e.src_func == "done" && e.dst_func.contains("go"))
        .map(|e| format!("{} -> {} @ {:?}", e.src_func, e.dst_func, e.dst_file))
        .collect();

    assert!(
        done_to_go.is_empty(),
        "self:go() inside A (which does not define `go`) must DECLINE the \
         unrelated same-file sibling bind (B:go / C:go), emitting no `done -> go` \
         edge; got: {done_to_go:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// NEVER-WORSE (own method): `A:done` calls `self:run()` and `A` DEFINES `run`
/// in the same file. The candidate `A:run` is the enclosing class's OWN method
/// (`colon_receiver == enclosing`), so the guard does not fire and the edge
/// `done -> run` STILL resolves to `A:run`. The fix must never drop a legitimate
/// self-dispatch to an own method.
#[test]
fn lua_self_colon_own_method_still_resolves() {
    let dir = std::env::temp_dir().join(format!("tldr_cl8_lua_own_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");

    std::fs::write(
        dir.join("mod.lua"),
        "function A:done()\n\
         \x20   self:run()\n\
         end\n\
         \n\
         function A:run()\n\
         \x20   return 1\n\
         end\n",
    )
    .unwrap();

    let graph = build_lua_graph(&dir);

    let has_done_to_run = graph
        .edges()
        .iter()
        .any(|e| e.src_func == "done" && e.dst_func.contains("run"));

    assert!(
        has_done_to_run,
        "self:run() inside A must STILL resolve to the own method A:run \
         (never-worse); edges: {:?}",
        graph
            .edges()
            .iter()
            .map(|e| format!("{} -> {}", e.src_func, e.dst_func))
            .collect::<Vec<_>>()
    );

    let _ = std::fs::remove_dir_all(&dir);
}
