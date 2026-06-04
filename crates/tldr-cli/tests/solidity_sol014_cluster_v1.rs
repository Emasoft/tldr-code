//! solidity-sol014-cluster-v1 (v0.5.0 SOL-014):
//!
//! Three TODOs landed in one cluster:
//!   M4. `vuln autodetect` routes `.sol` to `--lang solidity` (no need to
//!       pass `--lang solidity` explicitly).
//!   M5. `locked-ether` detector handles every payable shape:
//!       - `function foo() public payable`
//!       - `receive() external payable`
//!       - `fallback() external payable`
//!       - `constructor() public payable`
//!       …and every withdraw path:
//!       - `.transfer(...)`, `.send(...)`, `.call{value:...}(...)`,
//!         `payable(...).transfer(...)`, `selfdestruct(...)`,
//!         and any in-contract method that itself calls one of these
//!         (best-effort via tree-walk over the contract body).
//!   M6. The CLI VulnFinding.description (the `message` text in the
//!       JSON/SARIF output) is populated with a detector-specific
//!       human-readable string for each of the five Solidity detectors
//!       (`tx-origin`, `shadowing-state`, `suicidal`, `unchecked-lowlevel`,
//!       `locked-ether`) — non-empty AND non-generic.
//!
//! Each fixture is hermetic; no `/tmp/repos/...` dependency.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use tempfile::TempDir;
use tldr_core::security::vuln::{scan_vulnerabilities, VulnFinding, VulnType};

// =============================================================================
// Helpers
// =============================================================================

fn write_sol(filename: &str, content: &str) -> (TempDir, PathBuf) {
    let tmp = TempDir::new().expect("tempdir");
    let file = tmp.path().join(filename);
    fs::write(&file, content).expect("write fixture");
    (tmp, file)
}

fn findings_of(file: &PathBuf, ty: VulnType) -> Vec<VulnFinding> {
    let report = scan_vulnerabilities(file, None, None).expect("scan");
    report.findings.into_iter().filter(|f| f.vuln_type == ty).collect()
}

/// Path to the workspace's release `tldr` binary (canonical for integration
/// tests per the standing project rules).
fn tldr_bin() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // CARGO_MANIFEST_DIR = .../crates/tldr-cli ; binary lives at workspace
    // root target/release/tldr.
    p.pop();
    p.pop();
    p.push("target");
    p.push("release");
    p.push("tldr");
    p
}

// =============================================================================
// M4 — autodetect: .sol routes through scan_vulnerabilities without --lang
// =============================================================================

#[test]
fn m4_vuln_autodetect_sol_file_without_lang_flag() {
    // `tldr vuln <file>.sol` (NO --lang) should succeed and produce the same
    // findings as `tldr vuln <file>.sol --lang solidity`.
    let src = "\
pragma solidity ^0.8.0;
contract Auth {
    address owner;
    function withdraw() external {
        require(tx.origin == owner, \"not owner\");
    }
}
";
    let (_tmp, file) = write_sol("AutodetectSol.sol", src);
    let bin = tldr_bin();
    assert!(
        bin.exists(),
        "expected release tldr at {} — run `cargo build --release` first",
        bin.display()
    );

    // Autodetect path (no --lang).
    let auto = Command::new(&bin)
        .args(["vuln", file.to_str().unwrap(), "--format", "json"])
        .output()
        .expect("run tldr vuln autodetect");
    let auto_stdout = String::from_utf8_lossy(&auto.stdout).to_string();
    let auto_stderr = String::from_utf8_lossy(&auto.stderr).to_string();
    assert!(
        auto.status.success(),
        "autodetect path failed (exit {:?}); stderr:\n{auto_stderr}\nstdout:\n{auto_stdout}",
        auto.status.code()
    );

    // Explicit-lang path.
    let explicit = Command::new(&bin)
        .args([
            "vuln",
            file.to_str().unwrap(),
            "--lang",
            "solidity",
            "--format",
            "json",
        ])
        .output()
        .expect("run tldr vuln --lang solidity");
    let explicit_stdout = String::from_utf8_lossy(&explicit.stdout).to_string();
    assert!(explicit.status.success(), "explicit --lang solidity failed");

    // Both must report > 0 findings (the tx.origin require-check fixture).
    let auto_json: serde_json::Value =
        serde_json::from_str(&auto_stdout).expect("autodetect emitted JSON");
    let explicit_json: serde_json::Value =
        serde_json::from_str(&explicit_stdout).expect("explicit emitted JSON");

    let auto_n = auto_json["findings"].as_array().map(|a| a.len()).unwrap_or(0);
    let explicit_n = explicit_json["findings"]
        .as_array()
        .map(|a| a.len())
        .unwrap_or(0);

    assert!(
        auto_n > 0,
        "autodetect path produced 0 findings on a tx.origin fixture; stdout:\n{auto_stdout}"
    );
    assert_eq!(
        auto_n, explicit_n,
        "autodetect ({auto_n}) vs --lang solidity ({explicit_n}) finding count must match"
    );
}

// =============================================================================
// M5 — locked-ether: every payable shape × every withdraw shape
// =============================================================================

#[test]
fn m5_locked_ether_payable_function_no_withdraw_flagged() {
    let src = "\
pragma solidity ^0.8.0;
contract Vault {
    function deposit() public payable {}
    function noop() external pure {}
}
";
    let (_tmp, file) = write_sol("LockedFn.sol", src);
    let findings = findings_of(&file, VulnType::LockedEther);
    assert!(
        !findings.is_empty(),
        "`function deposit() public payable` + no withdraw must flag locked-ether"
    );
}

#[test]
fn m5_locked_ether_receive_payable_no_withdraw_flagged() {
    let src = "\
pragma solidity ^0.8.0;
contract Vault {
    receive() external payable {}
}
";
    let (_tmp, file) = write_sol("LockedRcv.sol", src);
    let findings = findings_of(&file, VulnType::LockedEther);
    assert!(
        !findings.is_empty(),
        "`receive() external payable` + no withdraw must flag locked-ether"
    );
}

#[test]
fn m5_locked_ether_fallback_payable_no_withdraw_flagged() {
    let src = "\
pragma solidity ^0.8.0;
contract Vault {
    fallback() external payable {}
}
";
    let (_tmp, file) = write_sol("LockedFb.sol", src);
    let findings = findings_of(&file, VulnType::LockedEther);
    assert!(
        !findings.is_empty(),
        "`fallback() external payable` + no withdraw must flag locked-ether"
    );
}

#[test]
fn m5_locked_ether_constructor_payable_no_withdraw_flagged() {
    let src = "\
pragma solidity ^0.8.0;
contract Vault {
    constructor() public payable {}
}
";
    let (_tmp, file) = write_sol("LockedCtor.sol", src);
    let findings = findings_of(&file, VulnType::LockedEther);
    assert!(
        !findings.is_empty(),
        "`constructor() public payable` + no withdraw must flag locked-ether"
    );
}

#[test]
fn m5_locked_ether_transfer_withdraw_not_flagged() {
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
    let (_tmp, file) = write_sol("LockedTransfer.sol", src);
    let findings = findings_of(&file, VulnType::LockedEther);
    assert!(
        findings.is_empty(),
        "`.transfer(...)` withdraw must NOT flag locked-ether; got {} findings",
        findings.len()
    );
}

#[test]
fn m5_locked_ether_send_withdraw_not_flagged() {
    let src = "\
pragma solidity ^0.8.0;
contract Vault {
    address payable owner;
    receive() external payable {}
    function withdraw() external {
        owner.send(address(this).balance);
    }
}
";
    let (_tmp, file) = write_sol("LockedSend.sol", src);
    let findings = findings_of(&file, VulnType::LockedEther);
    assert!(
        findings.is_empty(),
        "`.send(...)` withdraw must NOT flag locked-ether; got {} findings",
        findings.len()
    );
}

#[test]
fn m5_locked_ether_call_value_withdraw_not_flagged() {
    let src = "\
pragma solidity ^0.8.0;
contract Vault {
    address payable owner;
    receive() external payable {}
    function withdraw() external {
        (bool ok, ) = owner.call{value: address(this).balance}(\"\");
        require(ok, \"call failed\");
    }
}
";
    let (_tmp, file) = write_sol("LockedCallValue.sol", src);
    let findings = findings_of(&file, VulnType::LockedEther);
    assert!(
        findings.is_empty(),
        "`.call{{value:...}}(...)` withdraw must NOT flag locked-ether; got {} findings",
        findings.len()
    );
}

#[test]
fn m5_locked_ether_payable_cast_transfer_withdraw_not_flagged() {
    // `payable(owner).transfer(...)` is the explicit-cast withdraw shape
    // (used when `owner` is declared as `address` rather than `address
    // payable`).
    let src = "\
pragma solidity ^0.8.0;
contract Vault {
    address owner;
    receive() external payable {}
    function withdraw() external {
        payable(owner).transfer(address(this).balance);
    }
}
";
    let (_tmp, file) = write_sol("LockedPayCast.sol", src);
    let findings = findings_of(&file, VulnType::LockedEther);
    assert!(
        findings.is_empty(),
        "`payable(owner).transfer(...)` withdraw must NOT flag locked-ether; got {} findings",
        findings.len()
    );
}

#[test]
fn m5_locked_ether_selfdestruct_withdraw_not_flagged() {
    let src = "\
pragma solidity ^0.8.0;
contract Vault {
    address payable owner;
    receive() external payable {}
    function kill() external {
        require(msg.sender == owner, \"not owner\");
        selfdestruct(owner);
    }
}
";
    let (_tmp, file) = write_sol("LockedSelfdest.sol", src);
    let findings = findings_of(&file, VulnType::LockedEther);
    assert!(
        findings.is_empty(),
        "`selfdestruct(...)` withdraw must NOT flag locked-ether; got {} findings",
        findings.len()
    );
}

#[test]
fn m5_locked_ether_inherited_helper_withdraw_not_flagged() {
    // The withdraw call lives in a sibling helper method defined IN the
    // contract body. The detector's body-text walk must see this and NOT
    // flag the contract.
    let src = "\
pragma solidity ^0.8.0;
contract Vault {
    address payable owner;
    receive() external payable {}
    function _doWithdraw() internal {
        owner.transfer(address(this).balance);
    }
    function withdraw() external {
        _doWithdraw();
    }
}
";
    let (_tmp, file) = write_sol("LockedHelper.sol", src);
    let findings = findings_of(&file, VulnType::LockedEther);
    assert!(
        findings.is_empty(),
        "sibling-method withdraw must NOT flag locked-ether; got {} findings",
        findings.len()
    );
}

// =============================================================================
// M6 — finding messages: description is non-empty AND detector-specific.
// =============================================================================

/// Run the CLI and parse its JSON output. Returns `findings` array.
fn run_cli_vuln_json(file: &PathBuf) -> serde_json::Value {
    let bin = tldr_bin();
    let out = Command::new(&bin)
        .args(["vuln", file.to_str().unwrap(), "--lang", "solidity", "--format", "json"])
        .output()
        .expect("run tldr vuln");
    assert!(
        out.status.success(),
        "tldr vuln failed (exit {:?}); stderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    serde_json::from_str(&stdout).expect("CLI emitted JSON")
}

#[test]
fn m6_tx_origin_finding_has_message() {
    let src = "\
pragma solidity ^0.8.0;
contract Auth {
    address owner;
    function withdraw() external {
        require(tx.origin == owner, \"not owner\");
    }
}
";
    let (_tmp, file) = write_sol("Msg_TxOrigin.sol", src);
    let json = run_cli_vuln_json(&file);
    let findings = json["findings"].as_array().expect("findings array");
    let tx_origin: Vec<&serde_json::Value> = findings
        .iter()
        .filter(|f| f["vuln_type"].as_str() == Some("tx_origin"))
        .collect();
    assert!(!tx_origin.is_empty(), "no TxOrigin findings emitted");
    for f in tx_origin {
        let msg = f["description"].as_str().unwrap_or("");
        assert!(!msg.is_empty(), "tx-origin description must not be empty");
        assert!(
            msg.to_lowercase().contains("tx.origin"),
            "tx-origin description must mention tx.origin; got: {msg}"
        );
        // Must NOT carry the generic taint-style suffix.
        assert!(
            !msg.contains("with unsanitized input"),
            "tx-origin description carries generic taint suffix: {msg}"
        );
    }
}

#[test]
fn m6_shadowing_state_finding_has_message() {
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
    let (_tmp, file) = write_sol("Msg_Shadow.sol", src);
    let json = run_cli_vuln_json(&file);
    let findings = json["findings"].as_array().expect("findings array");
    let shadow: Vec<&serde_json::Value> = findings
        .iter()
        .filter(|f| f["vuln_type"].as_str() == Some("shadowing_state"))
        .collect();
    assert!(!shadow.is_empty(), "no ShadowingState findings emitted");
    for f in shadow {
        let msg = f["description"].as_str().unwrap_or("");
        assert!(!msg.is_empty(), "shadowing description must not be empty");
        assert!(
            msg.to_lowercase().contains("shadow"),
            "shadowing description must mention shadow; got: {msg}"
        );
        assert!(
            !msg.contains("with unsanitized input"),
            "shadowing description carries generic taint suffix: {msg}"
        );
    }
}

#[test]
fn m6_suicidal_finding_has_message() {
    let src = "\
pragma solidity ^0.8.0;
contract Bomb {
    function kill() public {
        selfdestruct(payable(msg.sender));
    }
}
";
    let (_tmp, file) = write_sol("Msg_Suicidal.sol", src);
    let json = run_cli_vuln_json(&file);
    let findings = json["findings"].as_array().expect("findings array");
    let s: Vec<&serde_json::Value> = findings
        .iter()
        .filter(|f| f["vuln_type"].as_str() == Some("suicidal"))
        .collect();
    assert!(!s.is_empty(), "no Suicidal findings emitted");
    for f in s {
        let msg = f["description"].as_str().unwrap_or("");
        assert!(!msg.is_empty(), "suicidal description must not be empty");
        assert!(
            msg.to_lowercase().contains("selfdestruct"),
            "suicidal description must mention selfdestruct; got: {msg}"
        );
        assert!(
            !msg.contains("with unsanitized input"),
            "suicidal description carries generic taint suffix: {msg}"
        );
    }
}

#[test]
fn m6_unchecked_lowlevel_finding_has_message() {
    let src = "\
pragma solidity ^0.8.0;
contract Caller {
    function notify(address target) external {
        target.call(\"\");
    }
}
";
    let (_tmp, file) = write_sol("Msg_Unchecked.sol", src);
    let json = run_cli_vuln_json(&file);
    let findings = json["findings"].as_array().expect("findings array");
    let u: Vec<&serde_json::Value> = findings
        .iter()
        .filter(|f| f["vuln_type"].as_str() == Some("unchecked_lowlevel"))
        .collect();
    assert!(!u.is_empty(), "no UncheckedLowlevel findings emitted");
    for f in u {
        let msg = f["description"].as_str().unwrap_or("");
        assert!(!msg.is_empty(), "unchecked-lowlevel description must not be empty");
        let lower = msg.to_lowercase();
        assert!(
            lower.contains("return value") || lower.contains("low-level") || lower.contains("call"),
            "unchecked-lowlevel description must describe the issue; got: {msg}"
        );
        assert!(
            !msg.contains("with unsanitized input"),
            "unchecked-lowlevel description carries generic taint suffix: {msg}"
        );
    }
}

#[test]
fn m6_locked_ether_finding_has_message() {
    let src = "\
pragma solidity ^0.8.0;
contract Vault {
    receive() external payable {}
    function noop() external pure {}
}
";
    let (_tmp, file) = write_sol("Msg_Locked.sol", src);
    let json = run_cli_vuln_json(&file);
    let findings = json["findings"].as_array().expect("findings array");
    let l: Vec<&serde_json::Value> = findings
        .iter()
        .filter(|f| f["vuln_type"].as_str() == Some("locked_ether"))
        .collect();
    assert!(!l.is_empty(), "no LockedEther findings emitted");
    for f in l {
        let msg = f["description"].as_str().unwrap_or("");
        assert!(!msg.is_empty(), "locked-ether description must not be empty");
        let lower = msg.to_lowercase();
        assert!(
            lower.contains("ether") || lower.contains("withdraw"),
            "locked-ether description must mention ether/withdraw; got: {msg}"
        );
        assert!(
            !msg.contains("with unsanitized input"),
            "locked-ether description carries generic taint suffix: {msg}"
        );
    }
}
