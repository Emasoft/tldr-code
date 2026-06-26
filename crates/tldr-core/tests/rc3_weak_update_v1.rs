//! rc3-element-write-as-killing-redefinition (v0.5.0 CLOSEOUT): characterization
//! tests for the WEAK (non-killing) element/field-write `RefType::WeakUpdate`.
//!
//! ROOT CAUSE: the DFG extractor emitted the SAME `RefType::Update` flavor for
//! three semantically different writes — an element/field write `xs[i] = v` /
//! `xs.f = v` (a USE of the base + a non-killing may-modify of its contents), a
//! whole-variable reassignment `xs = other()` (a STRONG, killing def), and an
//! op-assign `x += 1` (use-then-def STRONG). Reaching-defs then treated the
//! element write as a strong, killing redefinition of the WHOLE container, so
//! the earlier real definition lost its def-use chain (`uses == []`) and the
//! element-write line stole every later read.
//!
//! FIX: a distinct `RefType::WeakUpdate` flavor at the extractor boundary. It is
//! non-killing for reaching-defs / def-use / SSA / dead-stores / slice / PDG, but
//! STILL clobbers available-expressions (CSE). Whole-variable reassignment keeps
//! a STRONG `Update`; op-assign on a scalar keeps `Use`-then-`Update`.
//!
//! Each test asserts on the genuine signal — the DFG `refs` flavor or the
//! reaching-defs def-use chains — never on log text.

use std::path::PathBuf;
use tldr_core::cfg::get_cfg_context;
use tldr_core::dfg::get_dfg_context;
use tldr_core::dfg::reaching::build_reaching_defs_report;
use tldr_core::types::{Language, RefType};

/// (def_line, sorted use_lines) for every def-use chain of `var` in `function`.
fn chains_for(
    source: &str,
    function: &str,
    var: &str,
    lang: Language,
) -> Vec<(u32, Vec<u32>)> {
    let dfg = get_dfg_context(source, function, lang)
        .unwrap_or_else(|e| panic!("dfg failed for {function}: {e:?}"));
    let cfg = get_cfg_context(source, function, lang)
        .unwrap_or_else(|e| panic!("cfg failed for {function}: {e:?}"));
    let report = build_reaching_defs_report(&cfg, &dfg.refs, PathBuf::from("test"));
    let mut out: Vec<(u32, Vec<u32>)> = report
        .def_use_chains
        .iter()
        .filter(|c| c.definition.var == var)
        .map(|c| {
            let mut uses: Vec<u32> = c.uses.iter().map(|u| u.line).collect();
            uses.sort_unstable();
            (c.definition.line, uses)
        })
        .collect();
    out.sort_unstable();
    out
}

/// All `ref_type`s recorded for `var` at `line`.
fn ref_types_at(
    source: &str,
    function: &str,
    var: &str,
    line: u32,
    lang: Language,
) -> Vec<RefType> {
    let dfg = get_dfg_context(source, function, lang)
        .unwrap_or_else(|e| panic!("dfg failed for {function}: {e:?}"));
    dfg.refs
        .iter()
        .filter(|r| r.name == var && r.line == line)
        .map(|r| r.ref_type)
        .collect()
}

// =============================================================================
// 1. The fix — element/subscript write is NON-killing (JS + Python)
// =============================================================================

#[test]
fn js_element_write_does_not_kill_container() {
    // `var xs = make(); xs[0] = 1; return use(xs)`. The element write at line 3
    // must NOT kill the real def at line 2 — `xs@2` keeps the read at line 4,
    // and `xs@3` is not a def-use chain head.
    let src = "function f(){\n  var xs=make();\n  xs[0]=1;\n  return use(xs);\n}\n";
    assert_eq!(
        chains_for(src, "f", "xs", Language::JavaScript),
        vec![(2, vec![4])],
        "element write must not kill the container; xs@2 keeps use line 4"
    );
}

#[test]
fn python_element_write_does_not_kill_container() {
    let src = "def f():\n    xs = make()\n    xs[0] = 1\n    return use(xs)\n";
    assert_eq!(
        chains_for(src, "f", "xs", Language::Python),
        vec![(2, vec![4])],
        "python element write must not kill the container"
    );
}

// =============================================================================
// 2. CONTROL — a whole-variable reassignment MUST still kill (guards against a
//    blanket-suppress regression).
// =============================================================================

#[test]
fn js_whole_variable_reassignment_still_kills() {
    // `var xs = make(); xs = other(); return use(xs)`. Here the masking is
    // CORRECT: `xs@2` is killed (uses == []) and `xs@3` carries the read.
    let src = "function f(){\n  var xs=make();\n  xs=other();\n  return use(xs);\n}\n";
    assert_eq!(
        chains_for(src, "f", "xs", Language::JavaScript),
        vec![(2, vec![]), (3, vec![4])],
        "true reassignment must STILL kill the prior def"
    );
}

// =============================================================================
// 3. Struct/field-write generalization — `p.f = 1` does not kill `p`.
// =============================================================================

#[test]
fn js_field_write_does_not_kill_container() {
    let src = "function f(){\n  var p=mk();\n  p.field=1;\n  return use(p);\n}\n";
    assert_eq!(
        chains_for(src, "f", "p", Language::JavaScript),
        vec![(2, vec![4])],
        "field write `p.f=1` must not kill `p`"
    );
}

// =============================================================================
// 4. op-assign UNCHANGED — `x += 1` stays a STRONG (use-then-def) update.
// =============================================================================

#[test]
fn js_scalar_op_assign_still_strong() {
    // `var x = 0; x += 1; return use(x)`. The op-assign reads the prior value
    // (so `x@2` reaches the `+=` at line 3) and writes a NEW strong def `x@3`
    // that carries the later read at line 4. Confirms WeakUpdate did NOT
    // accidentally catch scalar `+=`.
    let src = "function f(){\n  var x=0;\n  x+=1;\n  return use(x);\n}\n";
    assert_eq!(
        chains_for(src, "f", "x", Language::JavaScript),
        vec![(2, vec![3]), (3, vec![4])],
        "scalar `x += 1` must remain a STRONG use-then-def update"
    );
    // And the op-assign line is a strong Update (not WeakUpdate).
    let types = ref_types_at(src, "f", "x", 3, Language::JavaScript);
    assert!(
        types.contains(&RefType::Update) && !types.contains(&RefType::WeakUpdate),
        "scalar op-assign must be Update, not WeakUpdate; got {types:?}"
    );
}

// =============================================================================
// 5. Extractor flavor — element/field write emits WeakUpdate; reassignment
//    emits a strong Update.
// =============================================================================

#[test]
fn element_write_container_is_weak_update() {
    let src = "function f(){\n  var xs=make();\n  xs[0]=1;\n}\n";
    let types = ref_types_at(src, "f", "xs", 3, Language::JavaScript);
    assert!(
        types.contains(&RefType::WeakUpdate),
        "`xs[0]=1` container must be WeakUpdate; got {types:?}"
    );
    assert!(
        !types.contains(&RefType::Update),
        "`xs[0]=1` container must NOT be a strong Update; got {types:?}"
    );
}

#[test]
fn reassignment_container_is_strong_not_weak() {
    // A whole-variable reassignment is a STRONG killing write. (The JS extractor
    // records the re-bind of a bare identifier as `Definition`; other languages
    // may use `Update`. Either is a strong, killing flavor — the invariant under
    // test is that it is NEVER the non-killing `WeakUpdate`.)
    let src = "function f(){\n  var xs=make();\n  xs=other();\n}\n";
    let types = ref_types_at(src, "f", "xs", 3, Language::JavaScript);
    assert!(
        types
            .iter()
            .any(|t| matches!(t, RefType::Definition | RefType::Update)),
        "`xs=other()` must be a strong (killing) write; got {types:?}"
    );
    assert!(
        !types.contains(&RefType::WeakUpdate),
        "`xs=other()` must NOT be a WeakUpdate; got {types:?}"
    );
}

// =============================================================================
// 6. Compound element write `xs[i] += v` — container is WeakUpdate (non-killing)
//    AND the base is read (R2 axis-2). WeakUpdate encodes the base read.
// =============================================================================

#[test]
fn compound_element_write_container_is_weak_update() {
    let src = "function f(){\n  var xs=make();\n  xs[0]+=1;\n  return use(xs);\n}\n";
    let types = ref_types_at(src, "f", "xs", 3, Language::JavaScript);
    assert!(
        types.contains(&RefType::WeakUpdate),
        "`xs[0]+=1` container must be WeakUpdate; got {types:?}"
    );
    // Non-killing: the real def at line 2 keeps the read at line 4.
    assert_eq!(
        chains_for(src, "f", "xs", Language::JavaScript),
        vec![(2, vec![4])],
        "compound element write must not kill the container"
    );
}

// =============================================================================
// 7. Rust positional-container edge (R2): `v[0] = 1` — the index_expression
//    container is positional (no `value` field) yet must still register the
//    container as WeakUpdate, keeping `v`'s prior def live.
// =============================================================================

#[test]
fn rust_positional_index_container_is_non_killing() {
    let src = "fn f() {\n    let mut v = mk();\n    v[0] = 1;\n    use_it(v);\n}\n";
    assert_eq!(
        chains_for(src, "f", "v", Language::Rust),
        vec![(2, vec![4])],
        "rust `v[0]=1` (positional container) must not kill the prior def"
    );
}

// =============================================================================
// 8. available-expressions CSE soundness — a weak element write MUST still
//    CLOBBER an available expression over the base.
// =============================================================================

#[test]
fn weak_element_write_still_clobbers_available_expr() {
    use tldr_core::dataflow::available::compute_available_exprs_with_source_and_lang;

    // `t = a[0] + 1; a[1] = 9; u = a[0] + 1`. The `a[1] = 9` weak update must
    // invalidate the available `a[0] + 1`, so the second computation is NOT a
    // redundant available expression. We assert the kill is recorded: `a`
    // appears in the block kill set (it would NOT if WeakUpdate were folded with
    // `Use` in available.rs — the cross-cluster soundness hole).
    let src = "function f(a){\n  var t = a[0] + 1;\n  a[1] = 9;\n  var u = a[0] + 1;\n  return t + u;\n}\n";
    let dfg = get_dfg_context(src, "f", Language::JavaScript).expect("dfg");
    let cfg = get_cfg_context(src, "f", Language::JavaScript).expect("cfg");
    let source_lines: Vec<String> = src.lines().map(|l| l.to_string()).collect();
    let info = compute_available_exprs_with_source_and_lang(
        &cfg,
        &dfg,
        &source_lines,
        Some(Language::JavaScript),
    )
    .expect("available");

    // The weak write `a[1] = 9` (line 3) clobbers any expression over `a`, so
    // at line 4 (the second `a[0] + 1`) NO expression with operand `a[0]` may be
    // reported available. If WeakUpdate were folded with `Use` in available.rs
    // (the cross-cluster soundness hole) the second computation would be wrongly
    // reported available — an unsound CSE.
    let avail_at_4 = info.get_available_at_line(4, &cfg);
    let leaked: Vec<String> = avail_at_4
        .iter()
        .filter(|e| e.operands.iter().any(|o| o.contains("a[0]")))
        .map(|e| e.text.clone())
        .collect();
    assert!(
        leaked.is_empty(),
        "weak element write `a[1]=9` must clobber the available `a[0]+1` for CSE \
         soundness; leaked available exprs at line 4: {leaked:?}"
    );

    // Sanity: the analysis DID see the expression (so the empty result above is
    // a genuine kill, not a parse miss).
    assert!(
        info.all_exprs
            .iter()
            .any(|e| e.operands.iter().any(|o| o.contains("a[0]"))),
        "expected the analysis to extract an `a[0]+1` expression"
    );
}
