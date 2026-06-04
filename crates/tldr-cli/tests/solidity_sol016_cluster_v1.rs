//! solidity-sol016-cluster-v1 (v0.5.0 SOL-016):
//!
//! Four TODOs landed in one cluster:
//!   M14. `tldr contracts <file>.sol <function>` extracts preconditions
//!        from `require(cond, "msg")` statements in the function body AND
//!        from NatSpec `@param NAME ...` tags + "Requirements:" sections
//!        inside the `@notice` / `@dev` text. Both surfaces compose.
//!   M15. `tldr taint` output's `tainted_vars` map strips any
//!        `_<digits>` SSA-version suffix from variable names so the JSON
//!        surface shows clean identifiers (e.g. `"x"` not `"x_1"`).
//!   M16. `tldr taint` registers Solidity sources and sinks:
//!        - sources: function parameters of `external`/`public` functions,
//!          `msg.sender`, `msg.value`, `msg.data`, `msg.sig`, `tx.origin`,
//!          `tx.gasprice`, return values of low-level calls.
//!        - sinks: `.call{value:...}(...)`, `.transfer(...)`, `.send(...)`,
//!          `.delegatecall(...)`, `.call(...)` (without value), `selfdestruct(...)`,
//!          `suicide(...)`, `assembly { ... }` blocks, and the reentrancy
//!          pattern (state-variable write that occurs AFTER an external
//!          call in the same function — flagged as a sink with a
//!          `post_external_call_write` note).
//!   M17. `tldr explain <file>.sol <func>` populates
//!        `signature.docstring` from the function's NatSpec `@notice` tag
//!        when present; falls back to the previous behaviour otherwise.
//!
//! Each fixture is hermetic.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use tempfile::TempDir;

// =============================================================================
// Helpers
// =============================================================================

fn write_sol(filename: &str, content: &str) -> (TempDir, PathBuf) {
    let tmp = TempDir::new().expect("tempdir");
    let file = tmp.path().join(filename);
    fs::write(&file, content).expect("write fixture");
    (tmp, file)
}

fn tldr_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_tldr"))
}

fn run_cli_json(args: &[&str]) -> serde_json::Value {
    let out = Command::new(tldr_bin())
        .args(args)
        .output()
        .expect("run tldr");
    assert!(
        out.status.success(),
        "tldr {:?} failed (exit {:?}); stderr:\n{}",
        args,
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("expected JSON; got: {}\nerror: {}", stdout, e))
}

// =============================================================================
// M14 — contracts: require() preconditions + NatSpec @param + "Requirements:"
// =============================================================================

#[test]
fn m14_contracts_extracts_require_calls_as_preconditions() {
    // require(cond, "msg") in the body should appear as a precondition.
    // The constraint text should preserve the human-readable message
    // when present, else the condition text.
    let (_tmp, file) = write_sol(
        "Require.sol",
        r#"
contract C {
    function withdraw(uint amount) external {
        require(amount > 0, "Positive only");
        require(amount < 1000);
    }
}
"#,
    );

    let report = run_cli_json(&[
        "contracts",
        file.to_str().unwrap(),
        "withdraw",
        "--format",
        "json",
    ]);

    let pre = report["preconditions"].as_array().expect("preconditions");

    // First require: the message OR the condition is in `constraint`.
    assert!(
        pre.iter().any(|c| {
            let cons = c["constraint"].as_str().unwrap_or("");
            cons.contains("amount > 0") || cons.contains("Positive only")
        }),
        "expected require(amount > 0, \"Positive only\") as precondition; got: {:#?}",
        pre
    );
    // Second require: condition only
    assert!(
        pre.iter().any(|c| {
            let cons = c["constraint"].as_str().unwrap_or("");
            cons.contains("amount < 1000")
        }),
        "expected require(amount < 1000) as precondition; got: {:#?}",
        pre
    );
}

#[test]
fn m14_contracts_extracts_require_and_natspec_requirements_section() {
    // Function carries BOTH a require() AND a NatSpec @param + a
    // "Requirements:" section inside @notice/@dev. All three should appear
    // as preconditions.
    let (_tmp, file) = write_sol(
        "Mix.sol",
        r#"
contract C {
    /// @notice Transfer tokens
    /// @param to recipient address
    /// @dev Requirements:
    /// - the caller must own enough balance
    /// - the recipient must be non-zero
    function transfer(address to, uint amount) public {
        require(amount > 0, "Positive only");
    }
}
"#,
    );

    let report = run_cli_json(&[
        "contracts",
        file.to_str().unwrap(),
        "transfer",
        "--format",
        "json",
    ]);
    let pre = report["preconditions"].as_array().expect("preconditions");

    // require() precondition is present
    assert!(
        pre.iter().any(|c| {
            let cons = c["constraint"].as_str().unwrap_or("");
            cons.contains("amount > 0") || cons.contains("Positive only")
        }),
        "expected require(amount > 0) precondition; got: {:#?}",
        pre
    );
    // NatSpec @param is present
    assert!(
        pre.iter().any(|c| {
            c["variable"] == "to"
                && c["constraint"]
                    .as_str()
                    .unwrap_or("")
                    .contains("recipient address")
        }),
        "expected NatSpec @param to as precondition; got: {:#?}",
        pre
    );
    // "Requirements:" lines parsed from NatSpec @dev as preconditions
    let req_constraints: Vec<&str> = pre
        .iter()
        .map(|c| c["constraint"].as_str().unwrap_or(""))
        .collect();
    assert!(
        req_constraints
            .iter()
            .any(|c| c.contains("caller must own enough balance")),
        "expected 'Requirements:' bullet 'caller must own enough balance' to appear as precondition; got: {:#?}",
        pre
    );
    assert!(
        req_constraints
            .iter()
            .any(|c| c.contains("recipient must be non-zero")),
        "expected 'Requirements:' bullet 'recipient must be non-zero' to appear as precondition; got: {:#?}",
        pre
    );
}

// =============================================================================
// M15 — taint: tainted_vars strips SSA `_<digits>` suffixes
// =============================================================================

#[test]
fn m15_taint_strips_ssa_suffix_from_tainted_vars() {
    // Even when SSA versioning is active and a variable is reassigned
    // multiple times, the tainted_vars JSON surface should report the
    // clean identifier "x" — never "x_1", "x_2", "x_3".
    let (_tmp, file) = write_sol(
        "Ssa.sol",
        r#"
contract C {
    function step(uint x) external {
        msg.sender.call{value: x}("");
        x = x + 1;
        x = x * 2;
        x = x - 3;
        msg.sender.call{value: x}("");
    }
}
"#,
    );

    let report = run_cli_json(&[
        "taint",
        file.to_str().unwrap(),
        "step",
        "--format",
        "json",
    ]);
    let tainted = report["tainted_vars"]
        .as_object()
        .expect("tainted_vars object");

    for (block, vars) in tainted {
        let arr = vars.as_array().expect("tainted_vars[block] array");
        for v in arr {
            let s = v.as_str().unwrap_or("");
            assert!(
                !ssa_versioned(s),
                "block {} contained SSA-versioned var '{}' (expected stripped); full set: {:#?}",
                block,
                s,
                tainted
            );
        }
    }
}

/// Returns true if `s` matches `<name>_<digits>` shape.
fn ssa_versioned(s: &str) -> bool {
    if let Some(idx) = s.rfind('_') {
        let tail = &s[idx + 1..];
        !tail.is_empty() && tail.chars().all(|c| c.is_ascii_digit())
    } else {
        false
    }
}

// =============================================================================
// M16 — taint: Solidity sources + sinks
// =============================================================================

#[test]
fn m16_taint_registers_msg_sender_as_source_and_call_as_sink() {
    // The canonical reentrancy-shaped function: external function takes
    // `amount`, calls msg.sender.call{value: amount}("") — both
    // msg.sender (source) and .call (sink) must register and a flow
    // from source → sink must appear.
    let (_tmp, file) = write_sol(
        "Withdraw.sol",
        r#"
contract C {
    function withdraw(uint amount) external {
        msg.sender.call{value: amount}("");
    }
}
"#,
    );

    let report = run_cli_json(&[
        "taint",
        file.to_str().unwrap(),
        "withdraw",
        "--format",
        "json",
    ]);
    let sources = report["sources"].as_array().expect("sources");
    let sinks = report["sinks"].as_array().expect("sinks");

    assert!(
        !sources.is_empty(),
        "expected at least one Solidity source (msg.sender / amount param); got: {:#?}",
        report
    );
    assert!(
        !sinks.is_empty(),
        "expected at least one Solidity sink (.call); got: {:#?}",
        report
    );
}

#[test]
fn m16_taint_flags_post_external_call_state_write_as_reentrancy() {
    // The vulnerable shape: external call happens BEFORE the state-variable
    // write. The post-external-call write should appear as a sink with a
    // `post_external_call_write` note.
    let (_tmp, file) = write_sol(
        "Reentrant.sol",
        r#"
contract C {
    mapping(address => uint) public balances;
    function withdraw(uint amount) external {
        require(balances[msg.sender] >= amount);
        msg.sender.call{value: amount}("");
        balances[msg.sender] -= amount;
    }
}
"#,
    );

    let report = run_cli_json(&[
        "taint",
        file.to_str().unwrap(),
        "withdraw",
        "--format",
        "json",
    ]);
    let sinks = report["sinks"].as_array().expect("sinks");

    let has_reentrancy = sinks.iter().any(|s| {
        let statement = s["statement"].as_str().unwrap_or("");
        let var = s["var"].as_str().unwrap_or("");
        statement.contains("post_external_call_write")
            || var.contains("post_external_call_write")
            || statement.to_lowercase().contains("post-external-call write")
    });
    assert!(
        has_reentrancy,
        "expected a sink flagging the post-external-call state write as reentrancy; sinks: {:#?}",
        sinks
    );
}

#[test]
fn m16_taint_no_reentrancy_when_state_write_precedes_external_call() {
    // CEI (checks-effects-interactions) ordering: state write happens
    // BEFORE the external call. No reentrancy sink should be flagged.
    let (_tmp, file) = write_sol(
        "Safe.sol",
        r#"
contract C {
    mapping(address => uint) public balances;
    function withdraw(uint amount) external {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        msg.sender.call{value: amount}("");
    }
}
"#,
    );

    let report = run_cli_json(&[
        "taint",
        file.to_str().unwrap(),
        "withdraw",
        "--format",
        "json",
    ]);
    let sinks = report["sinks"].as_array().expect("sinks");

    let has_reentrancy = sinks.iter().any(|s| {
        let statement = s["statement"].as_str().unwrap_or("");
        let var = s["var"].as_str().unwrap_or("");
        statement.contains("post_external_call_write")
            || var.contains("post_external_call_write")
            || statement.to_lowercase().contains("post-external-call write")
    });
    assert!(
        !has_reentrancy,
        "did NOT expect a reentrancy sink when state write precedes external call; sinks: {:#?}",
        sinks
    );
}

// =============================================================================
// M17 — explain: NatSpec @notice as docstring default for Solidity
// =============================================================================

#[test]
fn m17_explain_uses_natspec_notice_as_docstring() {
    let (_tmp, file) = write_sol(
        "Notice.sol",
        r#"
contract C {
    /// @notice Returns the sum of two numbers
    /// @param a first operand
    /// @param b second operand
    function add(uint a, uint b) public pure returns (uint) {
        return a + b;
    }
}
"#,
    );

    let report = run_cli_json(&[
        "explain",
        file.to_str().unwrap(),
        "add",
        "--format",
        "json",
    ]);
    let docstring = report["signature"]["docstring"]
        .as_str()
        .unwrap_or("");
    assert!(
        docstring.contains("Returns the sum of two numbers"),
        "expected @notice text as docstring; got '{}', report: {:#?}",
        docstring,
        report
    );
}

#[test]
fn m17_explain_no_natspec_yields_no_docstring_for_solidity() {
    // No NatSpec @notice → docstring is None (falls back to existing
    // behaviour; for Solidity that means absent because Solidity does
    // not have triple-quoted-string-body docstrings).
    let (_tmp, file) = write_sol(
        "Plain.sol",
        r#"
contract C {
    function noop(uint a) public pure returns (uint) {
        return a;
    }
}
"#,
    );

    let report = run_cli_json(&[
        "explain",
        file.to_str().unwrap(),
        "noop",
        "--format",
        "json",
    ]);
    // signature.docstring may be absent (skip_serializing_if) — that's fine.
    let docstring_present = report["signature"]
        .as_object()
        .map(|s| s.contains_key("docstring"))
        .unwrap_or(false);
    assert!(
        !docstring_present,
        "expected no docstring when @notice is absent; report: {:#?}",
        report
    );
}
