//! solidity-cfg-v1 (v0.5.0 SOL-005b): Solidity CFG decision-edge tests.
//!
//! Validates that the CFG extractor recognises Solidity's control-flow
//! constructs and emits the branch / back-edge / exit structure the
//! cyclomatic + downstream-metric pipeline depends on.
//!
//! Pre-fix state: `get_cfg_context(..., Language::Solidity)` returned an
//! essentially-flat CFG (cyclomatic=1, no decision edges) because:
//!   - tree-sitter-solidity wraps every statement in a `statement` named
//!     node — the generic `process_block` walker had no handler for it
//!     and dropped the body content.
//!   - `if_statement` exposes the then-branch and the else-branch as TWO
//!     children both bound to the `body` field name. `child_by_field_name`
//!     returns only the first, so the else-branch was invisible.
//!   - `try_statement` uses `attempt`/`body` fields with sibling
//!     `catch_clause` children — neither path matched the generic
//!     `"block"` / `"except_clause"` arms in `process_try_statement`.
//!   - `do_while_statement` was not recognised at all.
//!   - `revert_statement` was not treated as a function-exit.
//!
//! After this patch the per-Solidity dispatch in `process_statement` /
//! `process_if_statement` / `process_try_statement` produces the same
//! shape as Java's if / for / while / try arms.

use tldr_core::cfg::get_cfg_context;
use tldr_core::types::{BlockType, EdgeType, Language};

// -- if / else creates a branch --------------------------------------------

const IF_ELSE_SRC: &str = r#"
contract C {
  function classify(uint x) public pure returns (uint) {
    if (x > 0) {
      return 1;
    } else {
      return 2;
    }
  }
}
"#;

#[test]
fn if_else_creates_branch() {
    let cfg =
        get_cfg_context(IF_ELSE_SRC, "classify", Language::Solidity).expect("cfg ok");
    // if/else with two arms ⇒ cyclomatic >= 2 (one branch).
    assert!(
        cfg.cyclomatic_complexity >= 2,
        "expected cyclomatic >= 2 for if/else, got {} (edges={}, blocks={})",
        cfg.cyclomatic_complexity,
        cfg.edges.len(),
        cfg.blocks.len(),
    );
    let branch_count = cfg
        .blocks
        .iter()
        .filter(|b| b.block_type == BlockType::Branch)
        .count();
    assert!(
        branch_count >= 1,
        "expected at least one Branch block for if/else, got {}",
        branch_count
    );
    // Should have both a True and a False edge from the branch.
    let true_edges = cfg
        .edges
        .iter()
        .filter(|e| e.edge_type == EdgeType::True)
        .count();
    let false_edges = cfg
        .edges
        .iter()
        .filter(|e| e.edge_type == EdgeType::False)
        .count();
    assert!(
        true_edges >= 1 && false_edges >= 1,
        "expected >=1 True AND >=1 False edge for if/else, got True={}, False={}",
        true_edges,
        false_edges
    );
}

// -- while / for create a loop header with a back-edge ---------------------

const FOR_SRC: &str = r#"
contract C {
  function sum_to(uint n) public pure returns (uint) {
    uint s = 0;
    for (uint i = 0; i < n; i++) {
      s += i;
    }
    return s;
  }
}
"#;

#[test]
fn for_loop_creates_header_and_back_edge() {
    let cfg = get_cfg_context(FOR_SRC, "sum_to", Language::Solidity).expect("cfg ok");
    let loop_headers = cfg
        .blocks
        .iter()
        .filter(|b| b.block_type == BlockType::LoopHeader)
        .count();
    assert!(
        loop_headers >= 1,
        "expected >=1 LoopHeader for for, got {} (blocks={})",
        loop_headers,
        cfg.blocks.len()
    );
    let back_edges = cfg
        .edges
        .iter()
        .filter(|e| e.edge_type == EdgeType::BackEdge)
        .count();
    assert!(
        back_edges >= 1,
        "expected >=1 BackEdge for for, got {}",
        back_edges
    );
    assert!(
        cfg.cyclomatic_complexity >= 2,
        "expected cyclomatic >= 2 for for, got {}",
        cfg.cyclomatic_complexity
    );
}

const WHILE_SRC: &str = r#"
contract C {
  function count_down(uint n) public pure {
    while (n > 0) {
      n--;
    }
  }
}
"#;

#[test]
fn while_loop_creates_header_and_back_edge() {
    let cfg =
        get_cfg_context(WHILE_SRC, "count_down", Language::Solidity).expect("cfg ok");
    let loop_headers = cfg
        .blocks
        .iter()
        .filter(|b| b.block_type == BlockType::LoopHeader)
        .count();
    assert!(
        loop_headers >= 1,
        "expected >=1 LoopHeader for while, got {} (blocks={})",
        loop_headers,
        cfg.blocks.len()
    );
    let back_edges = cfg
        .edges
        .iter()
        .filter(|e| e.edge_type == EdgeType::BackEdge)
        .count();
    assert!(
        back_edges >= 1,
        "expected >=1 BackEdge for while, got {}",
        back_edges
    );
}

const DO_WHILE_SRC: &str = r#"
contract C {
  function bump(uint n) public pure returns (uint) {
    do {
      n++;
    } while (n < 5);
    return n;
  }
}
"#;

#[test]
fn do_while_loop_creates_header_and_back_edge() {
    let cfg =
        get_cfg_context(DO_WHILE_SRC, "bump", Language::Solidity).expect("cfg ok");
    let loop_headers = cfg
        .blocks
        .iter()
        .filter(|b| b.block_type == BlockType::LoopHeader)
        .count();
    assert!(
        loop_headers >= 1,
        "expected >=1 LoopHeader for do-while, got {} (blocks={})",
        loop_headers,
        cfg.blocks.len()
    );
    let back_edges = cfg
        .edges
        .iter()
        .filter(|e| e.edge_type == EdgeType::BackEdge)
        .count();
    assert!(
        back_edges >= 1,
        "expected >=1 BackEdge for do-while, got {}",
        back_edges
    );
}

// -- continue inside a loop jumps to the loop header -----------------------
//   (M-104 pattern — must NOT fall through past the continue.)

const CONTINUE_SRC: &str = r#"
contract C {
  function skip_one(uint n) public pure returns (uint) {
    uint s = 0;
    for (uint i = 0; i < n; i++) {
      if (i == 5) {
        continue;
      }
      s += i;
    }
    return s;
  }
}
"#;

#[test]
fn continue_inside_for_uses_continue_edge() {
    let cfg =
        get_cfg_context(CONTINUE_SRC, "skip_one", Language::Solidity).expect("cfg ok");
    let continue_edges = cfg
        .edges
        .iter()
        .filter(|e| e.edge_type == EdgeType::Continue)
        .count();
    assert!(
        continue_edges >= 1,
        "expected >=1 Continue edge inside for, got {} (edges={:#?})",
        continue_edges,
        cfg.edges.iter().map(|e| format!("{:?}", e.edge_type)).collect::<Vec<_>>()
    );
    // Loop must still have a back-edge.
    let back_edges = cfg
        .edges
        .iter()
        .filter(|e| e.edge_type == EdgeType::BackEdge)
        .count();
    assert!(
        back_edges >= 1,
        "expected >=1 BackEdge for the for-loop, got {}",
        back_edges
    );
}

// -- break inside a loop emits a Break edge --------------------------------

const BREAK_SRC: &str = r#"
contract C {
  function find_first(uint n) public pure returns (uint) {
    for (uint i = 0; i < n; i++) {
      if (i == 3) {
        break;
      }
    }
    return 0;
  }
}
"#;

#[test]
fn break_inside_for_emits_break_edge() {
    let cfg =
        get_cfg_context(BREAK_SRC, "find_first", Language::Solidity).expect("cfg ok");
    let break_edges = cfg
        .edges
        .iter()
        .filter(|e| e.edge_type == EdgeType::Break)
        .count();
    assert!(
        break_edges >= 1,
        "expected >=1 Break edge inside for, got {}",
        break_edges
    );
}

// -- try / catch creates an exception branch -------------------------------

const TRY_CATCH_SRC: &str = r#"
interface IFoo {
  function g() external returns (uint);
}
contract C {
  event E(uint v);
  function try_call(address t) public {
    try IFoo(t).g() returns (uint v) {
      emit E(v);
    } catch Error(string memory r) {
      revert(r);
    } catch (bytes memory) {
      revert("x");
    }
  }
}
"#;

#[test]
fn try_catch_creates_exception_branches() {
    let cfg = get_cfg_context(TRY_CATCH_SRC, "try_call", Language::Solidity)
        .expect("cfg ok");
    // try-body + 2 catch arms ⇒ at least 2 extra decision regions.
    // Cyclomatic should reflect at least 2 extra decision points + return
    // exits (revert).
    assert!(
        cfg.cyclomatic_complexity >= 2,
        "expected cyclomatic >= 2 for try/catch/catch, got {} (edges={}, blocks={})",
        cfg.cyclomatic_complexity,
        cfg.edges.len(),
        cfg.blocks.len(),
    );
    // Edges labelled with "exception" condition come from the try arm.
    let exception_edges = cfg
        .edges
        .iter()
        .filter(|e| e.condition.as_deref() == Some("exception"))
        .count();
    assert!(
        exception_edges >= 1,
        "expected >=1 'exception' edge for try/catch, got {} (all edges={:#?})",
        exception_edges,
        cfg.edges
            .iter()
            .map(|e| format!("{:?}/{:?}", e.edge_type, e.condition))
            .collect::<Vec<_>>()
    );
}

// -- require(false, ...) and revert create synthetic exit edges -----------

const REVERT_SRC: &str = r#"
contract C {
  function guarded(uint x) public pure returns (uint) {
    if (x == 0) {
      revert("zero");
    }
    return x;
  }
}
"#;

#[test]
fn revert_creates_exit_edge() {
    let cfg =
        get_cfg_context(REVERT_SRC, "guarded", Language::Solidity).expect("cfg ok");
    // revert must register at least one Exit block (mirrors return).
    let exit_blocks = cfg
        .blocks
        .iter()
        .filter(|b| b.block_type == BlockType::Exit)
        .count();
    assert!(
        exit_blocks >= 1,
        "expected >=1 Exit block for revert(...), got {} (blocks={:#?})",
        exit_blocks,
        cfg.blocks.iter().map(|b| format!("{:?}", b.block_type)).collect::<Vec<_>>()
    );
}

const REQUIRE_SRC: &str = r#"
contract C {
  function guarded(uint x) public pure returns (uint) {
    require(x > 0, "non-zero");
    return x;
  }
}
"#;

#[test]
fn require_creates_branch_and_exit() {
    let cfg = get_cfg_context(REQUIRE_SRC, "guarded", Language::Solidity)
        .expect("cfg ok");
    // require(cond, ...) lowers to: branch on cond → continue OR exit.
    // We require at least one Branch block AND at least one Exit block.
    let branch_count = cfg
        .blocks
        .iter()
        .filter(|b| b.block_type == BlockType::Branch)
        .count();
    let exit_count = cfg
        .blocks
        .iter()
        .filter(|b| b.block_type == BlockType::Exit)
        .count();
    assert!(
        branch_count >= 1,
        "expected >=1 Branch block for require(), got {} (blocks={:#?})",
        branch_count,
        cfg.blocks
            .iter()
            .map(|b| format!("{:?}", b.block_type))
            .collect::<Vec<_>>()
    );
    assert!(
        exit_count >= 1,
        "expected >=1 Exit block for require(), got {}",
        exit_count
    );
    assert!(
        cfg.cyclomatic_complexity >= 2,
        "expected cyclomatic >= 2 for require() (branch), got {}",
        cfg.cyclomatic_complexity
    );
}

// -- return statement counted as an exit ----------------------------------

const RETURN_SRC: &str = r#"
contract C {
  function plain() public pure returns (uint) {
    return 42;
  }
}
"#;

#[test]
fn return_creates_exit_block() {
    let cfg =
        get_cfg_context(RETURN_SRC, "plain", Language::Solidity).expect("cfg ok");
    let exit_blocks = cfg
        .blocks
        .iter()
        .filter(|b| b.block_type == BlockType::Exit)
        .count();
    assert!(
        exit_blocks >= 1,
        "expected >=1 Exit block for return, got {}",
        exit_blocks
    );
}

// -- unchecked { ... } block is a transparent container ------------------

const UNCHECKED_SRC: &str = r#"
contract C {
  function bump(uint x) public pure returns (uint) {
    unchecked {
      if (x > 0) {
        x = x + 1;
      }
    }
    return x;
  }
}
"#;

#[test]
fn unchecked_block_does_not_swallow_inner_branches() {
    let cfg =
        get_cfg_context(UNCHECKED_SRC, "bump", Language::Solidity).expect("cfg ok");
    // The if-inside-unchecked must still register a branch.
    let branch_count = cfg
        .blocks
        .iter()
        .filter(|b| b.block_type == BlockType::Branch)
        .count();
    assert!(
        branch_count >= 1,
        "expected >=1 Branch block inside unchecked {{...}}, got {} (blocks={:#?})",
        branch_count,
        cfg.blocks.iter().map(|b| format!("{:?}", b.block_type)).collect::<Vec<_>>()
    );
}
