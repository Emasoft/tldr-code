//! solidity-sol015a-interface-surface-v1 (v0.5.0 SOL-015a):
//! integration tests for two paired Solidity polish items:
//!
//! - **M7** (`tldr interface <file>.sol`): the per-language dispatch in
//!   `crates/tldr-cli/src/commands/patterns/interface.rs` previously
//!   returned `methods: []` and `bases: []` for every Solidity
//!   `contract_declaration` because `method_node_kinds` and
//!   `extract_base_classes` had no Solidity arm.
//! - **M8** (`tldr surface <file>.sol`): when a Solidity target had an
//!   empty package qualifier, the qualified_name reconstruction in
//!   `crates/tldr-core/src/surface/solidity.rs` could emit
//!   `..ContractName` (leading double-dot from an empty parent join).
//!
//! These tests are hermetic — they synthesize the Solidity fixture and
//! invoke the public APIs directly, no `/tmp/repos` corpus dependency.

use std::fs;
use tempfile::TempDir;

use tldr_cli::commands::patterns::interface::extract_interface;
use tldr_core::surface::extract_api_surface;

const TOKEN_VAULT: &str = "\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Token vault
contract TokenVault is Ownable, ReentrancyGuard {
    uint256 public totalDeposits;
    uint256 internal _internalCounter;

    event Deposit(address indexed user, uint256 amount);
    error InsufficientBalance(uint256 available, uint256 required);
    modifier nonReentrant() { _; }

    constructor() {}

    fallback() external payable {}
    receive() external payable {}

    function deposit(uint256 amount) external payable nonReentrant returns (bool) {
        totalDeposits += amount;
        return true;
    }

    function withdraw(uint256 amount) public returns (bool) {
        return true;
    }

    function _internalHelper(uint256 x) internal pure returns (uint256) {
        return x + 1;
    }

    function _privateHelper() private pure returns (uint256) {
        return 0;
    }
}
";

fn write_fixture(name: &str, src: &str) -> (TempDir, std::path::PathBuf) {
    let tmp = TempDir::new().unwrap();
    let file = tmp.path().join(name);
    fs::write(&file, src).unwrap();
    (tmp, file)
}

// =============================================================================
// M7: `tldr interface` populates methods + bases for Solidity contracts
// =============================================================================

#[test]
fn interface_solidity_contract_emits_bases() {
    let (_tmp, file) = write_fixture("TokenVault.sol", TOKEN_VAULT);
    let src = fs::read_to_string(&file).unwrap();
    let info = extract_interface(&file, &src).expect("interface extraction should succeed");

    let class = info
        .classes
        .iter()
        .find(|c| c.name == "TokenVault")
        .expect("expected TokenVault class in interface output");

    assert!(
        class.bases.iter().any(|b| b == "Ownable"),
        "expected `Ownable` in bases; got {:?}",
        class.bases
    );
    assert!(
        class.bases.iter().any(|b| b == "ReentrancyGuard"),
        "expected `ReentrancyGuard` in bases; got {:?}",
        class.bases
    );
}

#[test]
fn interface_solidity_contract_emits_methods() {
    let (_tmp, file) = write_fixture("TokenVault.sol", TOKEN_VAULT);
    let src = fs::read_to_string(&file).unwrap();
    let info = extract_interface(&file, &src).expect("interface extraction should succeed");

    let class = info
        .classes
        .iter()
        .find(|c| c.name == "TokenVault")
        .expect("expected TokenVault class");
    let names: Vec<&str> = class.methods.iter().map(|m| m.name.as_str()).collect();

    // External / public methods MUST surface.
    assert!(
        names.contains(&"deposit"),
        "expected external method `deposit`; got {:?}",
        names
    );
    assert!(
        names.contains(&"withdraw"),
        "expected public method `withdraw`; got {:?}",
        names
    );
    // Internal / private methods MUST NOT surface as public methods.
    assert!(
        !names.contains(&"_internalHelper"),
        "internal `_internalHelper` must not appear in public methods; got {:?}",
        names
    );
    assert!(
        !names.contains(&"_privateHelper"),
        "private `_privateHelper` must not appear in public methods; got {:?}",
        names
    );
}

#[test]
fn interface_solidity_interface_decl_emits_methods() {
    const SRC: &str = "\
pragma solidity ^0.8.0;
interface IFoo is IBase {
    function bar(uint256 x) external returns (bool);
    function baz() external;
}
";
    let (_tmp, file) = write_fixture("IFoo.sol", SRC);
    let src = fs::read_to_string(&file).unwrap();
    let info = extract_interface(&file, &src).expect("interface extraction should succeed");

    let class = info
        .classes
        .iter()
        .find(|c| c.name == "IFoo")
        .expect("expected IFoo class");
    let names: Vec<&str> = class.methods.iter().map(|m| m.name.as_str()).collect();

    assert!(
        names.contains(&"bar"),
        "expected `bar` in interface methods; got {:?}",
        names
    );
    assert!(
        names.contains(&"baz"),
        "expected `baz` in interface methods; got {:?}",
        names
    );
    assert!(
        class.bases.iter().any(|b| b == "IBase"),
        "expected `IBase` in bases; got {:?}",
        class.bases
    );
}

#[test]
fn interface_solidity_library_emits_methods() {
    const SRC: &str = "\
pragma solidity ^0.8.0;
library SafeMath {
    function add(uint256 a, uint256 b) internal pure returns (uint256) { return a + b; }
    function mul(uint256 a, uint256 b) public pure returns (uint256) { return a * b; }
}
";
    let (_tmp, file) = write_fixture("SafeMath.sol", SRC);
    let src = fs::read_to_string(&file).unwrap();
    let info = extract_interface(&file, &src).expect("interface extraction should succeed");

    let class = info
        .classes
        .iter()
        .find(|c| c.name == "SafeMath")
        .expect("expected SafeMath class");
    let names: Vec<&str> = class.methods.iter().map(|m| m.name.as_str()).collect();

    // Public library fn surfaces; internal fn does not.
    assert!(
        names.contains(&"mul"),
        "expected `mul` (public) in library methods; got {:?}",
        names
    );
    assert!(
        !names.contains(&"add"),
        "internal `add` must not appear in public methods; got {:?}",
        names
    );
}

// =============================================================================
// M8: surface `qualified_name` never has a leading `..` (double-dot)
// =============================================================================

#[test]
fn surface_solidity_qualified_name_has_no_double_dot_prefix() {
    let (_tmp, file) = write_fixture("TokenVault.sol", TOKEN_VAULT);
    let s = extract_api_surface(file.to_str().unwrap(), Some("solidity"), false, None, None)
        .expect("surface extraction should succeed");

    for entry in &s.apis {
        assert!(
            !entry.qualified_name.starts_with(".."),
            "qualified_name must not start with `..`, got {:?}",
            entry.qualified_name
        );
    }
    // And the contract qualified_name must contain the bare name segment.
    assert!(
        s.apis
            .iter()
            .any(|a| a.qualified_name.ends_with(".TokenVault")
                || a.qualified_name == "TokenVault"),
        "expected a `TokenVault` qualified_name entry; got {:?}",
        s.apis
            .iter()
            .map(|a| a.qualified_name.clone())
            .collect::<Vec<_>>()
    );
}

#[test]
fn surface_solidity_file_scope_function_has_no_leading_dot() {
    const SRC: &str = "\
pragma solidity ^0.8.0;
function topLevelHelper(uint256 x) pure returns (uint256) {
    return x + 1;
}
";
    let (_tmp, file) = write_fixture("FreeFn.sol", SRC);
    let s = extract_api_surface(file.to_str().unwrap(), Some("solidity"), false, None, None)
        .expect("surface extraction should succeed");

    let entry = s
        .apis
        .iter()
        .find(|a| a.qualified_name.ends_with("topLevelHelper"))
        .unwrap_or_else(|| {
            panic!(
                "expected `topLevelHelper` qualified_name; got {:?}",
                s.apis
                    .iter()
                    .map(|a| a.qualified_name.clone())
                    .collect::<Vec<_>>()
            )
        });

    assert!(
        !entry.qualified_name.starts_with(".."),
        "qualified_name must not start with `..`, got {:?}",
        entry.qualified_name
    );
    assert!(
        !entry.qualified_name.starts_with('.'),
        "qualified_name must not start with `.`, got {:?}",
        entry.qualified_name
    );
}
