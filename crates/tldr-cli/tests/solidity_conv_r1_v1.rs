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
// M15 — DESIGN JUDGEMENT (not mechanical): the `tainted_vars` map is
// declared as `HashMap<usize, HashSet<String>>` and is keyed by CFG
// **block id** (not SSA version or identifier). The audit-time
// observation that the JSON keys were `"0"`, `"1"` was correct, but the
// keys are not SSA numbers — they're block IDs, which is the
// documented schema (see `TaintInfo` in
// `crates/tldr-core/src/security/taint.rs:258` and the spec test
// `test_taint_info_struct_fields` in `security/taint_tests.rs:234`).
// Identifier-name flow info is already preserved on `sources[].var` and
// `sinks[].var`. Switching the dict-key shape would break the
// documented schema and the existing block-keyed `is_tainted(block_id,
// var)` query API across the codebase. Flagged in `new_gaps[]` for
// human review.
//
// (No test asserts in this section — see report design_gaps[].)


// ==========================================================================
// M17 — explain: Solidity `summary` defaults to NatSpec @notice
// ==========================================================================

#[test]
fn m17_explain_summary_defaults_to_natspec_notice_for_solidity() {
    // The audit referred to `summary` as "the user-facing one-line
    // description on the explain surface". The schema field is
    // `signature.docstring` (no top-level `summary` exists on
    // ExplainReport). When a Solidity function carries a NatSpec
    // `@notice` it MUST appear on `signature.docstring`.
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

    let docstring = report["signature"]["docstring"].as_str().unwrap_or("");
    assert!(
        !docstring.is_empty(),
        "expected signature.docstring to default to NatSpec @notice on Solidity; got: {:#?}",
        report["signature"]["docstring"]
    );
    assert!(
        docstring.contains("doubled"),
        "expected docstring to reflect @notice content 'doubled'; got: {:?}",
        docstring
    );
}

// v0.5.0 SOL-CONV-R1-3 (M17): when @notice is absent (the OZ ERC20
// `_transfer` shape), the @dev text becomes the fallback summary so
// internal functions documented only with `@dev` still surface a
// human-readable docstring.
#[test]
fn m17_explain_summary_falls_back_to_natspec_dev_when_notice_missing() {
    let (_tmp, file) = write_sol(
        "Explaindev.sol",
        r#"
contract C {
    /// @dev Internal helper that doubles its input.
    /// @param x the input
    function _double(uint x) internal pure returns (uint) {
        return x * 2;
    }
}
"#,
    );

    let report = run_cli_json(&[
        "explain",
        file.to_str().unwrap(),
        "_double",
        "--format",
        "json",
    ]);

    let docstring = report["signature"]["docstring"].as_str().unwrap_or("");
    assert!(
        !docstring.is_empty(),
        "expected signature.docstring to fall back to NatSpec @dev when @notice is absent; got: {:#?}",
        report["signature"]["docstring"]
    );
    assert!(
        docstring.contains("Internal helper") || docstring.contains("doubles"),
        "expected docstring to reflect @dev content; got: {:?}",
        docstring
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

    // The contracts step lives at `sub_results.contracts.data` (an
    // array of per-function `ContractsReport` objects). The
    // project-scan must emit one entry per documented function — pre-fix
    // the array was empty for Solidity because the extractor harvested
    // only file-scope free functions, skipping contract members.
    let data = &report["sub_results"]["contracts"]["data"];
    let arr = data
        .as_array()
        .unwrap_or_else(|| panic!("expected sub_results.contracts.data to be an array; got: {:#?}", data));
    assert!(
        !arr.is_empty(),
        "expected verify.sub_results.contracts.data to enumerate per-function reports on \
         Solidity project-scan; got empty array (full report: {:#?})",
        report
    );

    // Both functions must appear: `a` and `b`.
    let function_names: Vec<&str> = arr
        .iter()
        .filter_map(|item| item["function"].as_str())
        .collect();
    assert!(
        function_names.contains(&"a"),
        "expected function `a` in verify contracts.data; got: {:?}",
        function_names
    );
    assert!(
        function_names.contains(&"b"),
        "expected function `b` in verify contracts.data; got: {:?}",
        function_names
    );
}
