//! solidity-vuln-v1 (v0.5.0 SOL-011): top-5 Solidity vulnerability detectors.
//!
//! AST-based detectors operating on the canonical
//! `tldr_core::security::vuln::scan_vulnerabilities` pipeline. These
//! detectors run a separate Solidity-only branch that does not depend on
//! the taint engine (the vulnerabilities are language-shape patterns, not
//! data-flow flows).
//!
//! Coverage (1 positive + 1 negative test per detector):
//!   1. `tx-origin`           — `tx.origin` used in auth condition.
//!   2. `shadowing-state`     — local/param shadows contract state var.
//!   3. `suicidal`            — public/external selfdestruct without
//!                              access control modifier.
//!   4. `unchecked-lowlevel`  — `.call(...)` / `.send(...)` /
//!                              `.delegatecall(...)` return value discarded.
//!   5. `locked-ether`        — payable function with no withdraw path.
//!
//! Each fixture is hermetic; no `/tmp/repos/...` dependency.

use std::fs;
use std::path::PathBuf;

use tempfile::TempDir;
use tldr_core::security::vuln::{scan_vulnerabilities, VulnType};

/// Helper: write `content` to `<tmpdir>/<filename>` and return both the
/// `TempDir` (so caller holds the lifetime) and the file path.
fn write_sol(filename: &str, content: &str) -> (TempDir, PathBuf) {
    let tmp = TempDir::new().expect("tempdir");
    let file = tmp.path().join(filename);
    fs::write(&file, content).expect("write fixture");
    (tmp, file)
}

/// Helper: run `scan_vulnerabilities` on `file` and return findings with
/// `vuln_type == ty`.
fn findings_of(file: &PathBuf, ty: VulnType) -> Vec<tldr_core::security::vuln::VulnFinding> {
    let report = scan_vulnerabilities(file, None, None).expect("scan");
    report
        .findings
        .into_iter()
        .filter(|f| f.vuln_type == ty)
        .collect()
}

// =============================================================================
// 1. tx-origin
// =============================================================================

#[test]
fn tx_origin_positive_require_check_flagged() {
    // `require(tx.origin == owner)` is the canonical tx.origin auth
    // anti-pattern: phishing-prone because tx.origin is the EOA at the
    // root of the call chain.
    let src = "\
pragma solidity ^0.8.0;
contract Auth {
    address owner;
    function withdraw() external {
        require(tx.origin == owner, \"not owner\");
    }
}
";
    let (_tmp, file) = write_sol("TxOriginBad.sol", src);
    let findings = findings_of(&file, VulnType::TxOrigin);
    assert!(
        !findings.is_empty(),
        "tx.origin in require should be flagged; got 0 findings"
    );
}

#[test]
fn tx_origin_negative_msg_sender_not_flagged() {
    // `msg.sender` is the immediate caller and is NOT the anti-pattern.
    let src = "\
pragma solidity ^0.8.0;
contract Auth {
    address owner;
    function withdraw() external {
        require(msg.sender == owner, \"not owner\");
    }
}
";
    let (_tmp, file) = write_sol("TxOriginGood.sol", src);
    let findings = findings_of(&file, VulnType::TxOrigin);
    assert!(
        findings.is_empty(),
        "msg.sender auth must NOT be flagged; got {} findings",
        findings.len()
    );
}

// =============================================================================
// 2. shadowing-state
// =============================================================================

#[test]
fn shadowing_state_positive_local_shadows_state_var() {
    // Local `balance` shadows contract state `balance` — classic
    // assignment-bug seed.
    let src = "\
pragma solidity ^0.8.0;
contract Wallet {
    uint256 balance;
    function deposit(uint256 amount) external {
        uint256 balance = amount;
        emit Logged(balance);
    }
    event Logged(uint256);
}
";
    let (_tmp, file) = write_sol("ShadowBad.sol", src);
    let findings = findings_of(&file, VulnType::ShadowingState);
    assert!(
        !findings.is_empty(),
        "shadowing local must be flagged; got 0 findings"
    );
}

#[test]
fn shadowing_state_negative_distinct_names_not_flagged() {
    let src = "\
pragma solidity ^0.8.0;
contract Wallet {
    uint256 balance;
    function deposit(uint256 amount) external {
        uint256 newBalance = balance + amount;
        emit Logged(newBalance);
    }
    event Logged(uint256);
}
";
    let (_tmp, file) = write_sol("ShadowGood.sol", src);
    let findings = findings_of(&file, VulnType::ShadowingState);
    assert!(
        findings.is_empty(),
        "distinct local-name must NOT be flagged; got {} findings",
        findings.len()
    );
}

// =============================================================================
// 3. suicidal
// =============================================================================

#[test]
fn suicidal_positive_unguarded_selfdestruct_flagged() {
    // public `kill()` that calls selfdestruct with no access guard.
    let src = "\
pragma solidity ^0.8.0;
contract Bomb {
    function kill() public {
        selfdestruct(payable(msg.sender));
    }
}
";
    let (_tmp, file) = write_sol("SuicidalBad.sol", src);
    let findings = findings_of(&file, VulnType::Suicidal);
    assert!(
        !findings.is_empty(),
        "unguarded selfdestruct must be flagged; got 0 findings"
    );
}

#[test]
fn suicidal_negative_onlyowner_guarded_not_flagged() {
    let src = "\
pragma solidity ^0.8.0;
contract Bomb {
    modifier onlyOwner() { _; }
    function kill() public onlyOwner {
        selfdestruct(payable(msg.sender));
    }
}
";
    let (_tmp, file) = write_sol("SuicidalGood.sol", src);
    let findings = findings_of(&file, VulnType::Suicidal);
    assert!(
        findings.is_empty(),
        "onlyOwner-guarded selfdestruct must NOT be flagged; got {} findings",
        findings.len()
    );
}

// =============================================================================
// 4. unchecked-lowlevel
// =============================================================================

#[test]
fn unchecked_lowlevel_positive_discarded_call_return_flagged() {
    // `.call(...)` in an expression statement discards the (bool,bytes)
    // return tuple — the return-value-NOT-checked anti-pattern.
    let src = "\
pragma solidity ^0.8.0;
contract Caller {
    function notify(address target) external {
        target.call(\"\");
    }
}
";
    let (_tmp, file) = write_sol("UncheckedBad.sol", src);
    let findings = findings_of(&file, VulnType::UncheckedLowlevel);
    assert!(
        !findings.is_empty(),
        "discarded .call() must be flagged; got 0 findings"
    );
}

#[test]
fn unchecked_lowlevel_negative_require_wrapped_not_flagged() {
    let src = "\
pragma solidity ^0.8.0;
contract Caller {
    function notify(address target) external {
        (bool ok, ) = target.call(\"\");
        require(ok, \"call failed\");
    }
}
";
    let (_tmp, file) = write_sol("UncheckedGood.sol", src);
    let findings = findings_of(&file, VulnType::UncheckedLowlevel);
    assert!(
        findings.is_empty(),
        "checked .call() must NOT be flagged; got {} findings",
        findings.len()
    );
}

// =============================================================================
// 5. locked-ether
// =============================================================================

#[test]
fn locked_ether_positive_payable_no_withdraw_flagged() {
    // Contract receives ether via `receive()` (payable) but provides no
    // withdraw path (.transfer / .send / .call{value:} / selfdestruct).
    let src = "\
pragma solidity ^0.8.0;
contract Vault {
    receive() external payable {}
    function noop() external pure {}
}
";
    let (_tmp, file) = write_sol("LockedBad.sol", src);
    let findings = findings_of(&file, VulnType::LockedEther);
    assert!(
        !findings.is_empty(),
        "payable-no-withdraw must be flagged; got 0 findings"
    );
}

#[test]
fn locked_ether_negative_has_withdraw_not_flagged() {
    let src = "\
pragma solidity ^0.8.0;
contract Vault {
    address payable owner;
    receive() external payable {}
    function withdraw() external {
        owner.transfer(address(this).balance);
    }
}
";
    let (_tmp, file) = write_sol("LockedGood.sol", src);
    let findings = findings_of(&file, VulnType::LockedEther);
    assert!(
        findings.is_empty(),
        "has-withdraw must NOT be flagged; got {} findings",
        findings.len()
    );
}
