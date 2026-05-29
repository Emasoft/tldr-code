//! cfg-per-lang-decision-edges-v1 (v0.4.2 M-103)
//!
//! Validates that the CFG extractor recognises language-specific control
//! flow constructs in Elixir, Kotlin, and Swift and emits the
//! decision-edge structure the cyclomatic / edge-count metrics depend on.
//!
//! Pre-fix state (iter-2 audit `/tmp/audit_phase22/iter2/`):
//! - **Elixir**: `cond do`, `case do`, `try/rescue/catch/after` produce
//!   `cyclomatic = 1, num_edges = 0` — the AST nodes (top-level `call`
//!   targets `"try"`/`"case"`/`"cond"` with `do_block` containers and
//!   `stab_clause` arms) are not wired into CFG branch emission.
//! - **Kotlin**: a `for` loop containing `if (cond) continue` /
//!   `if (cond) break` reports `cyclomatic = 2, num_blocks = 5,
//!   num_edges = 2` — a structurally impossible connected graph. The
//!   `for_statement`'s body block is not iterated, so nested
//!   `if_expression` nodes never reach the branch processor.
//! - **Swift**: `guard ... else { … }`, `do { … } catch { … }`, and
//!   `switch x { case … }` arms each add zero decision edges; cyclomatic
//!   stays at 1 even with three switch arms.
//!
//! After this fix the per-language node kinds are recognised in
//! `process_statement`/`process_block` and produce branch + join blocks
//! exactly like the Python/Rust/Java equivalents already do.
//!
//! Tests use `tldr_core::cfg::get_cfg_context` directly so they do not
//! depend on a pre-built release binary.

use tldr_core::cfg::get_cfg_context;
use tldr_core::types::{BlockType, EdgeType, Language};

// -- Arm 1: Elixir cond/case/try ------------------------------------------

const ELIXIR_SRC: &str = r#"defmodule Probe do
  def with_try(x) do
    try do
      do_work(x)
    rescue
      e in RuntimeError -> handle_rt(e)
    catch
      :exit, val -> handle_exit(val)
    after
      cleanup()
    end
  end

  def shape(x) do
    case x do
      0 -> :zero
      n when n > 0 -> :pos
      _ -> :neg
    end
  end

  def process(x) do
    cond do
      x > 10 -> :big
      x > 0 -> :small
      true -> :zero
    end
  end
end
"#;

#[test]
fn elixir_try_rescue_catch_after_adds_decision_edges() {
    let cfg = get_cfg_context(ELIXIR_SRC, "with_try", Language::Elixir)
        .expect("cfg ok");
    // try-body + rescue + catch + after = 4 control regions. Cyclomatic
    // must reflect at least 3 extra decision points beyond the baseline.
    assert!(
        cfg.cyclomatic_complexity >= 3,
        "expected cyclomatic >= 3 for try/rescue/catch/after, got {} (edges={}, blocks={})",
        cfg.cyclomatic_complexity,
        cfg.edges.len(),
        cfg.blocks.len(),
    );
    assert!(
        cfg.edges.len() >= 4,
        "expected >=4 CFG edges for try/rescue/catch/after, got {}",
        cfg.edges.len()
    );
    // Must have at least one branch block representing the try dispatch.
    let branch_count = cfg
        .blocks
        .iter()
        .filter(|b| b.block_type == BlockType::Branch)
        .count();
    assert!(
        branch_count >= 1,
        "expected at least one Branch block for try/rescue/catch, got {}",
        branch_count
    );
}

#[test]
fn elixir_case_do_three_arms_adds_decision_edges() {
    let cfg = get_cfg_context(ELIXIR_SRC, "shape", Language::Elixir)
        .expect("cfg ok");
    // `case do` with 3 arms ⇒ cyclomatic >= 3.
    assert!(
        cfg.cyclomatic_complexity >= 3,
        "expected cyclomatic >= 3 for `case do` 3-arm, got {} (edges={}, blocks={})",
        cfg.cyclomatic_complexity,
        cfg.edges.len(),
        cfg.blocks.len(),
    );
    // Three arm-targets means at least one True + two False decision edges.
    let true_edges = cfg.edges.iter().filter(|e| e.edge_type == EdgeType::True).count();
    let false_edges = cfg.edges.iter().filter(|e| e.edge_type == EdgeType::False).count();
    assert!(
        true_edges + false_edges >= 3,
        "expected >=3 decision (True+False) edges for case arms, got True={}, False={}",
        true_edges,
        false_edges
    );
}

#[test]
fn elixir_cond_do_three_arms_adds_decision_edges() {
    let cfg = get_cfg_context(ELIXIR_SRC, "process", Language::Elixir)
        .expect("cfg ok");
    assert!(
        cfg.cyclomatic_complexity >= 3,
        "expected cyclomatic >= 3 for `cond do` 3-arm, got {} (edges={}, blocks={})",
        cfg.cyclomatic_complexity,
        cfg.edges.len(),
        cfg.blocks.len(),
    );
    let true_edges = cfg.edges.iter().filter(|e| e.edge_type == EdgeType::True).count();
    let false_edges = cfg.edges.iter().filter(|e| e.edge_type == EdgeType::False).count();
    assert!(
        true_edges + false_edges >= 3,
        "expected >=3 decision edges for cond arms, got True={}, False={}",
        true_edges,
        false_edges
    );
}

// -- Arm 2: Kotlin if-inside-for ------------------------------------------

const KOTLIN_SRC: &str = r#"fun continueProbe(items: List<Int>): Int {
    var sum = 0
    for (i in items) {
        if (i < 0) continue
        if (i > 100) break
        sum += i
    }
    return sum
}
"#;

#[test]
fn kotlin_if_inside_for_recurses_into_branches() {
    let cfg = get_cfg_context(KOTLIN_SRC, "continueProbe", Language::Kotlin)
        .expect("cfg ok");
    // baseline 1 + for-loop (back edge) + 2× if-expression = at least 4
    assert!(
        cfg.cyclomatic_complexity >= 4,
        "expected cyclomatic >= 4 for for + 2 if-statements, got {} (edges={}, blocks={})",
        cfg.cyclomatic_complexity,
        cfg.edges.len(),
        cfg.blocks.len(),
    );
    // A connected CFG with N blocks needs at least N-1 edges; the audit
    // observed 5 blocks with 2 edges (impossible). Sanity-check the
    // post-fix invariant explicitly.
    let n = cfg.blocks.len();
    let e = cfg.edges.len();
    assert!(
        e + 1 >= n,
        "CFG structurally invalid: N={} blocks but only E={} edges (need >= N-1)",
        n,
        e,
    );
    assert!(
        cfg.edges.len() >= 4,
        "expected >=4 CFG edges (for + 2 ifs), got {}",
        cfg.edges.len()
    );
    // The if-expressions must reach the branch processor.
    let branch_blocks = cfg
        .blocks
        .iter()
        .filter(|b| b.block_type == BlockType::Branch)
        .count();
    assert!(
        branch_blocks >= 2,
        "expected >=2 Branch blocks (one per nested if), got {}",
        branch_blocks
    );
}

// -- Arm 3: Swift guard / do-catch / switch arms --------------------------

const SWIFT_SRC: &str = r#"func unwrapMany(x: Int?, y: Int?) -> Int {
    guard let xv = x, let yv = y else { return -1 }
    return xv + yv
}

func tryCatch() -> Int {
    do {
        try doSomething()
        return 0
    } catch {
        return -1
    }
}

func switchCase(x: Int) -> String {
    switch x {
    case 0: return "zero"
    case 1, 2: return "one_two"
    default: return "other"
    }
}
"#;

#[test]
fn swift_guard_statement_adds_decision_branch() {
    let cfg = get_cfg_context(SWIFT_SRC, "unwrapMany", Language::Swift)
        .expect("cfg ok");
    // guard introduces an alternative exit path ⇒ cyclomatic >= 2.
    assert!(
        cfg.cyclomatic_complexity >= 2,
        "expected cyclomatic >= 2 for guard-else, got {} (edges={}, blocks={})",
        cfg.cyclomatic_complexity,
        cfg.edges.len(),
        cfg.blocks.len(),
    );
    let branch_blocks = cfg
        .blocks
        .iter()
        .filter(|b| b.block_type == BlockType::Branch)
        .count();
    assert!(
        branch_blocks >= 1,
        "expected >=1 Branch block for guard, got {}",
        branch_blocks
    );
}

#[test]
fn swift_do_catch_adds_decision_branch() {
    let cfg = get_cfg_context(SWIFT_SRC, "tryCatch", Language::Swift)
        .expect("cfg ok");
    // do-body + catch arm = at least 2 decision points.
    assert!(
        cfg.cyclomatic_complexity >= 2,
        "expected cyclomatic >= 2 for do-catch, got {} (edges={}, blocks={})",
        cfg.cyclomatic_complexity,
        cfg.edges.len(),
        cfg.blocks.len(),
    );
    assert!(
        cfg.edges.len() >= 3,
        "expected >=3 CFG edges for do-catch, got {}",
        cfg.edges.len()
    );
}

#[test]
fn swift_switch_three_arms_adds_decision_edges() {
    let cfg = get_cfg_context(SWIFT_SRC, "switchCase", Language::Swift)
        .expect("cfg ok");
    // case 0 / case 1,2 / default = 3 arms ⇒ cyclomatic >= 3.
    assert!(
        cfg.cyclomatic_complexity >= 3,
        "expected cyclomatic >= 3 for switch with 3 arms, got {} (edges={}, blocks={})",
        cfg.cyclomatic_complexity,
        cfg.edges.len(),
        cfg.blocks.len(),
    );
    let true_edges = cfg.edges.iter().filter(|e| e.edge_type == EdgeType::True).count();
    let false_edges = cfg.edges.iter().filter(|e| e.edge_type == EdgeType::False).count();
    assert!(
        true_edges + false_edges >= 3,
        "expected >=3 decision edges for switch arms, got True={}, False={}",
        true_edges,
        false_edges
    );
}
