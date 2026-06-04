//! solidity-convergence-r1-v1 (v0.5.0 SOL-CONV-R1):
//!
//! Round-1 extra-round mechanical gap fixes uncovered by the OpenZeppelin
//! v5.0.2 ERC20 corpus on iter-N audits.
//!
//! Gaps closed here:
//!   M14b. `tldr contracts <file>.sol <func>` lifts body-level
//!         `if (cond) revert Error();` (and `if (cond) { revert ...; }`)
//!         patterns into preconditions, mirroring how `require(cond, "msg")`
//!         is already lifted. ERC20 in OZ v5 uses the if/revert variant
//!         exclusively, so prior to this fix `_transfer` returned an empty
//!         `preconditions` array even though the body has multiple guards.
//!   M15.  `tldr taint` already emits SSA-stripped names on `sources[].var`
//!         and `sinks[].var`, but the `tainted_vars` MAP key is the raw
//!         SSA number (e.g., `"0"`, `"1"`). The key must be the
//!         identifier name instead so downstream consumers can look up
//!         flows by symbol.
//!   M17.  `tldr explain <file>.sol <func>` emits `summary == null` for
//!         Solidity functions even when the function carries a NatSpec
//!         `@notice` tag. The summary should default to the trimmed
//!         `@notice` text.
//!   C20.  `tldr context "Contract::func" --project . --depth 3` returns
//!         exactly one function for Solidity (no transitive expansion).
//!         The Solidity call-graph adapter is wired, but the context
//!         builder's depth expansion stops at depth 1 because it does not
//!         recognise Solidity callee qnames. The expansion must follow
//!         the call graph at every depth, matching every other language.
//!   V11.  `tldr verify .` on a multi-file Solidity project iterates
//!         per-file and runs every analysis, but the `contracts` step's
//!         project-scan loop only enumerates files — it does not call
//!         the per-function NatSpec extractor. Single-file `tldr contracts
//!         <file> <func>` works; the project-scan path returns zero
//!         items even when the file has multiple documented functions.
//!
//! Each fixture is hermetic; no shared corpus is required.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use tempfile::TempDir;

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

// ==========================================================================
// M14b — contracts: lift body-level `if (cond) revert Error()` to preconditions
// ==========================================================================

#[test]
fn m14b_if_revert_braceless_lifts_to_precondition() {
    // Single-statement consequence (no braces): ERC20's canonical guard.
    let (_tmp, file) = write_sol(
        "Ifrevert.sol",
        r#"
contract C {
    error ZeroAddress();
    error InsufficientBalance(uint have, uint need);

    function transfer(address to, uint amount) external {
        if (to == address(0)) revert ZeroAddress();
        if (amount == 0) revert InsufficientBalance(0, amount);
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

    assert!(
        !pre.is_empty(),
        "expected if-revert preconditions on transfer; got: {:#?}",
        pre
    );
    // The 'to == address(0)' guard implies a precondition `to != address(0)`.
    assert!(
        pre.iter().any(|c| {
            let cons = c["constraint"].as_str().unwrap_or("");
            cons.contains("to") && (cons.contains("!=") || cons.contains("address(0)"))
        }),
        "expected if (to == address(0)) revert ... to yield a precondition mentioning `to` / `address(0)`; got: {:#?}",
        pre
    );
    // The 'amount == 0' guard implies `amount != 0`.
    assert!(
        pre.iter().any(|c| {
            let cons = c["constraint"].as_str().unwrap_or("");
            cons.contains("amount")
        }),
        "expected if (amount == 0) revert ... to yield a precondition mentioning `amount`; got: {:#?}",
        pre
    );
}

#[test]
fn m14b_if_revert_block_lifts_to_precondition() {
    // Braced consequence: `if (cond) { revert Error(); }`.
    let (_tmp, file) = write_sol(
        "IfrevertBlock.sol",
        r#"
contract C {
    error TooLarge(uint);
    function set(uint amount) external {
        if (amount > 1000) {
            revert TooLarge(amount);
        }
    }
}
"#,
    );

    let report = run_cli_json(&[
        "contracts",
        file.to_str().unwrap(),
        "set",
        "--format",
        "json",
    ]);
    let pre = report["preconditions"].as_array().expect("preconditions");

    assert!(
        !pre.is_empty(),
        "expected if-revert block precondition; got: {:#?}",
        pre
    );
    assert!(
        pre.iter().any(|c| {
            let cons = c["constraint"].as_str().unwrap_or("");
            cons.contains("amount")
        }),
        "expected guard precondition mentioning `amount`; got: {:#?}",
        pre
    );
}

// ==========================================================================
// M15 — taint tainted_vars dict key uses identifier name (not SSA index)
// ==========================================================================

#[test]
fn m15_taint_tainted_vars_keys_are_identifier_names_not_ssa_numbers() {
    let (_tmp, file) = write_sol(
        "Taintkeys.sol",
        r#"
contract C {
    function f(address to) external payable {
        // assignment that should propagate taint to `dest`
        address dest = to;
        // tainted call
        (bool ok, ) = dest.call{value: msg.value}("");
        ok;
    }
}
"#,
    );

    let report = run_cli_json(&[
        "taint",
        file.to_str().unwrap(),
        "f",
        "--format",
        "json",
    ]);

    let tv = report["tainted_vars"]
        .as_object()
        .expect("tainted_vars must be an object");

    // The fix: keys are identifier names — never bare SSA-number strings.
    for k in tv.keys() {
        let trimmed = k.trim();
        assert!(
            !trimmed.chars().all(|c| c.is_ascii_digit()),
            "tainted_vars key {:?} looks like a raw SSA index; expected identifier name. \
             Full map: {:#?}",
            trimmed,
            tv
        );
    }
}

// ==========================================================================
// M17 — explain: Solidity `summary` defaults to NatSpec @notice
// ==========================================================================

#[test]
fn m17_explain_summary_defaults_to_natspec_notice_for_solidity() {
    let (_tmp, file) = write_sol(
        "Explainnotice.sol",
        r#"
contract C {
    /// @notice Returns the doubled amount.
    /// @param x the input
    function doubleIt(uint x) external pure returns (uint) {
        return x * 2;
    }
}
"#,
    );

    let report = run_cli_json(&[
        "explain",
        file.to_str().unwrap(),
        "doubleIt",
        "--format",
        "json",
    ]);

    let summary = report["summary"].as_str().unwrap_or("");
    assert!(
        !summary.is_empty(),
        "expected explain.summary to default to NatSpec @notice on Solidity; got: {:#?}",
        report["summary"]
    );
    assert!(
        summary.contains("doubled"),
        "expected summary to reflect @notice content 'doubled'; got: {:?}",
        summary
    );
}

// ==========================================================================
// C20 — context Solidity transitive expansion respects --depth
// ==========================================================================

#[test]
fn c20_context_solidity_depth_expands_callees_transitively() {
    let (tmp, _file) = write_sol(
        "Depth.sol",
        r#"
contract C {
    function caller() external {
        helper();
    }
    function helper() internal {
        leaf();
    }
    function leaf() internal pure {}
}
"#,
    );
    // Run `tldr context` with --project pointing at the tempdir.
    let proj = tmp.path().to_str().unwrap();
    let report = run_cli_json(&[
        "context",
        "C::caller",
        "--project",
        proj,
        "--depth",
        "3",
        "--format",
        "json",
    ]);

    // The returned set should include the transitive callees as the
    // depth expands. Accept either flat `functions` array or a `nodes`
    // structure depending on the shape.
    let body = serde_json::to_string(&report).unwrap_or_default();
    assert!(
        body.contains("helper"),
        "expected depth>=2 expansion to include helper; got: {}",
        body
    );
    assert!(
        body.contains("leaf"),
        "expected depth>=3 expansion to include leaf; got: {}",
        body
    );
}

// ==========================================================================
// V11 — verify project-scan invokes contracts NatSpec extractor per function
// ==========================================================================

#[test]
fn v11_verify_project_scan_runs_contracts_per_function() {
    // Build a multi-function .sol file under a temp project root.
    let (tmp, _file) = write_sol(
        "Project.sol",
        r#"
contract C {
    /// @notice First doc.
    function a() external pure returns (uint) { return 1; }

    /// @notice Second doc.
    function b() external pure returns (uint) { return 2; }
}
"#,
    );
    let proj = tmp.path().to_str().unwrap();
    let report = run_cli_json(&[
        "verify",
        proj,
        "--format",
        "json",
    ]);

    // The contracts step should emit at least one item (the per-function
    // contract surface), not be empty.
    let contracts = &report["contracts"];
    // Accept either a `total` field or array shape. Fail when empty.
    let empty = match contracts {
        serde_json::Value::Object(map) => {
            let total = map
                .get("total")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let items_len = map
                .get("items")
                .and_then(|v| v.as_array())
                .map(|a| a.len() as u64)
                .unwrap_or(0);
            let funcs_len = map
                .get("functions")
                .and_then(|v| v.as_array())
                .map(|a| a.len() as u64)
                .unwrap_or(0);
            total == 0 && items_len == 0 && funcs_len == 0
        }
        serde_json::Value::Array(a) => a.is_empty(),
        _ => true,
    };
    assert!(
        !empty,
        "expected verify.contracts to enumerate per-function NatSpec data on multi-file Solidity \
         project-scan; got empty: {:#?}",
        contracts
    );
}
