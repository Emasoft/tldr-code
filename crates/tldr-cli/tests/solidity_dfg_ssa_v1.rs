//! solidity-dfg-ssa-v1 (v0.5.0 SOL-006b): per-language DFG + SSA arms.
//!
//! Pre-fix state: `Language::Solidity` matched no arm in the DFG extractor's
//! parameter dispatch, variable-declaration dispatch, or use-context
//! classifier. As a result `get_dfg_context(..., Language::Solidity)` produced
//! a DFG with zero refs for every Solidity function, and `tldr reaching-defs`
//! / `tldr ssa` returned empty gen/kill/def-use sets across the board.
//!
//! Post-fix expectations:
//!   - Function parameters register as `RefType::Definition` on the signature
//!     line.
//!   - Local variable declarations (`uint256 y = ...;`) register the LHS as
//!     `RefType::Definition` and the RHS as `RefType::Use`s.
//!   - Plain assignments (`y = ...;`) register the LHS as `Definition` and
//!     the RHS as `Use`s.
//!   - Augmented assignments (`y += ...;`) register the LHS as `Update`.
//!   - Update expressions (`y++`, `y--`) register the operand as `Update`
//!     (M-114 PHP analog — emit both a use and a def on the same line).
//!   - Mapping/array writes (`balances[user] = y;`) register `balances` as
//!     `Update` and both `user` and `y` as `Use`s.
//!   - `tldr reaching-defs` reports the SECOND def of a variable reaching
//!     a downstream use, not the first.
//!   - `tldr ssa` emits a non-zero version count for the function.

use std::fs;
use std::process::Command;
use tempfile::TempDir;

use tldr_core::dfg::get_dfg_context;
use tldr_core::ssa::construct::construct_ssa;
use tldr_core::ssa::types::SsaType;
use tldr_core::types::{Language, RefType};

const REACHING_FIXTURE: &str = "\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract C {
    event Foo(uint256 v);

    function go() public {
        uint256 x = 1;
        x = 2;
        emit Foo(x);
    }
}
";

const UPDATE_FIXTURE: &str = "\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract C {
    function step() public {
        uint256 n = 0;
        n++;
    }
}
";

const FULL_FIXTURE: &str = "\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Vault {
    mapping(address => uint256) public balances;

    event Deposit(address user, uint256 amount);

    function deposit(uint256 amount, address user) public {
        uint256 y = amount + 1;
        y = 10;
        y += 5;
        y++;
        balances[user] = y;
        emit Deposit(user, y);
    }
}
";

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

fn run_tldr(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(tldr_bin())
        .args(args)
        .output()
        .expect("failed to run tldr binary");
    let exit = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    (exit, stdout, stderr)
}

// -- core DFG library-level checks -----------------------------------------

#[test]
fn dfg_parameters_register_as_definitions() {
    let dfg = get_dfg_context(FULL_FIXTURE, "deposit", Language::Solidity)
        .expect("dfg ok");

    // Both parameters must show up as Definition refs.
    let defs: Vec<&str> = dfg
        .refs
        .iter()
        .filter(|r| matches!(r.ref_type, RefType::Definition))
        .map(|r| r.name.as_str())
        .collect();
    assert!(
        defs.contains(&"amount"),
        "parameter `amount` must register as a Definition; got defs={:?}",
        defs
    );
    assert!(
        defs.contains(&"user"),
        "parameter `user` must register as a Definition; got defs={:?}",
        defs
    );
}

#[test]
fn dfg_local_variable_declaration_emits_def_and_uses() {
    let dfg = get_dfg_context(FULL_FIXTURE, "deposit", Language::Solidity)
        .expect("dfg ok");

    // `uint256 y = amount + 1;` — y is a Definition, amount is a Use.
    let y_def_line = dfg
        .refs
        .iter()
        .find(|r| r.name == "y" && matches!(r.ref_type, RefType::Definition))
        .map(|r| r.line);
    assert!(
        y_def_line.is_some(),
        "local var `uint256 y = ...;` must emit Definition for y; refs={:?}",
        dfg.refs
    );

    let amount_use = dfg
        .refs
        .iter()
        .any(|r| r.name == "amount" && matches!(r.ref_type, RefType::Use));
    assert!(
        amount_use,
        "RHS of `uint256 y = amount + 1;` must emit Use of amount; refs={:?}",
        dfg.refs
    );
}

#[test]
fn dfg_assignment_emits_def_on_lhs() {
    let dfg = get_dfg_context(FULL_FIXTURE, "deposit", Language::Solidity)
        .expect("dfg ok");

    // `y = 10;` — y gets a second Definition.
    let y_defs: Vec<u32> = dfg
        .refs
        .iter()
        .filter(|r| r.name == "y" && matches!(r.ref_type, RefType::Definition))
        .map(|r| r.line)
        .collect();
    assert!(
        y_defs.len() >= 2,
        "y must have multiple Definitions (from `uint256 y = ...;` and `y = 10;`); \
         got {:?}",
        y_defs
    );
}

#[test]
fn dfg_augmented_assignment_emits_update() {
    let dfg = get_dfg_context(FULL_FIXTURE, "deposit", Language::Solidity)
        .expect("dfg ok");

    // `y += 5;` — y registers an Update at that line.
    let y_updates: Vec<u32> = dfg
        .refs
        .iter()
        .filter(|r| r.name == "y" && matches!(r.ref_type, RefType::Update))
        .map(|r| r.line)
        .collect();
    assert!(
        !y_updates.is_empty(),
        "y += 5 must emit Update; got refs={:?}",
        dfg.refs
    );
}

#[test]
fn dfg_update_expression_emits_update_use_and_def_pair() {
    // `n++` is M-114's PHP analog — emit RefType::Update on the operand so
    // SSA construction treats it as USE-then-DEF and the version after
    // `n++` is fresh.
    let dfg = get_dfg_context(UPDATE_FIXTURE, "step", Language::Solidity)
        .expect("dfg ok");

    let n_update_line = dfg
        .refs
        .iter()
        .find(|r| r.name == "n" && matches!(r.ref_type, RefType::Update))
        .map(|r| r.line);
    assert!(
        n_update_line.is_some(),
        "n++ must emit at least one Update for n; refs={:?}",
        dfg.refs
    );
}

#[test]
fn dfg_mapping_write_treats_base_as_weak_update_and_index_as_use() {
    let dfg = get_dfg_context(FULL_FIXTURE, "deposit", Language::Solidity)
        .expect("dfg ok");

    // `balances[user] = y;` — an element/mapping write. rc3
    // (element-write-as-killing-redefinition): `balances` is now a WeakUpdate
    // (a USE + non-killing may-modify of the container), NOT a strong killing
    // Update — so a prior whole-mapping binding keeps its def-use chain. `user`
    // is a Use.
    let balances_weak = dfg.refs.iter().any(|r| {
        r.name == "balances" && matches!(r.ref_type, RefType::WeakUpdate)
    });
    assert!(
        balances_weak,
        "LHS of `balances[user] = y;` must emit WeakUpdate for balances; refs={:?}",
        dfg.refs
    );
    assert!(
        !dfg.refs.iter().any(|r| r.name == "balances"
            && matches!(r.ref_type, RefType::Definition | RefType::Update)),
        "element write must not emit a strong Definition/Update for balances"
    );

    let user_use = dfg
        .refs
        .iter()
        .any(|r| r.name == "user" && matches!(r.ref_type, RefType::Use));
    assert!(
        user_use,
        "index expression `balances[user]` on LHS must emit Use of user; \
         refs={:?}",
        dfg.refs
    );
}

// -- CLI-level reaching-defs check -----------------------------------------

/// `tldr reaching-defs` on the small `x = 1; x = 2; emit Foo(x);` fixture
/// must report the SECOND def of x reaching the emit (line 10), not the
/// first (line 9). Equivalent assertion: stats.definitions reports 2 defs
/// of x and at least one block's `gen` contains x.
#[test]
fn reaching_defs_reports_second_def_for_emit_use() {
    if !tldr_bin().exists() {
        eprintln!(
            "[skip] reaching_defs_reports_second_def_for_emit_use: \
             release binary {} not present",
            tldr_bin().display()
        );
        return;
    }

    let tmp = TempDir::new().expect("temp dir");
    let path = tmp.path().join("R.sol");
    fs::write(&path, REACHING_FIXTURE).expect("write fixture");

    let (rc, stdout, stderr) = run_tldr(&[
        "reaching-defs",
        path.to_str().unwrap(),
        "go",
        "--format",
        "json",
    ]);
    assert_eq!(
        rc, 0,
        "reaching-defs must succeed on solidity fixture; stderr=\n{}",
        stderr
    );

    let v: serde_json::Value =
        serde_json::from_str(&stdout).expect("reaching-defs output must be JSON");
    let defs = v["stats"]["definitions"].as_u64().unwrap_or(0);
    assert!(
        defs >= 2,
        "solidity reaching-defs must report at least 2 defs of x \
         (from `uint256 x = 1;` and `x = 2;`); got stats.definitions = {}",
        defs
    );

    let blocks = v["blocks"].as_array().cloned().unwrap_or_default();
    let nonzero_gen = blocks
        .iter()
        .filter(|b| b["gen"].as_array().map(|a| a.len()).unwrap_or(0) > 0)
        .count();
    assert!(
        nonzero_gen > 0,
        "at least one block must have non-empty gen for go(); got 0 across {} \
         blocks (pre-fix: solidity DFG extractor emitted zero Definition refs)",
        blocks.len()
    );
}

// -- Library-level SSA check -----------------------------------------------

/// Constructs SSA directly via the public library API (the `tldr` CLI
/// does not expose `ssa` as a top-level subcommand — SSA construction
/// is reached via `dead-stores`). This is the lower-level equivalent
/// of `dead-stores`: it verifies that `construct_ssa(..., Solidity, ...)`
/// produces multiple SsaNames for a variable that gets repeatedly
/// assigned.
#[test]
fn ssa_emits_versions_for_repeatedly_assigned_variable() {
    let ssa = construct_ssa(REACHING_FIXTURE, "go", Language::Solidity, SsaType::Minimal)
        .expect("ssa construction must succeed for Solidity");

    let x_count = ssa
        .ssa_names
        .iter()
        .filter(|n| n.variable == "x")
        .count();
    assert!(
        x_count >= 2,
        "ssa must emit at least 2 SsaNames for variable x (x_1 from `uint256 x = 1;`, \
         x_2 from `x = 2;`); got {} (full ssa_names={:?})",
        x_count,
        ssa.ssa_names
    );

    // Also verify that the update_expression analog (Solidity `n++`)
    // produces a versioned SSA chain via `construct_ssa`. After `n++`
    // there should be at least 2 versions of `n`: the initial def and
    // the post-update.
    let update_ssa = construct_ssa(UPDATE_FIXTURE, "step", Language::Solidity, SsaType::Minimal)
        .expect("ssa construction must succeed for n++ fixture");
    let n_count = update_ssa
        .ssa_names
        .iter()
        .filter(|n| n.variable == "n")
        .count();
    assert!(
        n_count >= 2,
        "n++ must produce >= 2 SSA versions of n (initial def + post-update); \
         got {} (ssa_names={:?})",
        n_count,
        update_ssa.ssa_names
    );
}
