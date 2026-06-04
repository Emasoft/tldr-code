//! solidity-surface-v1 (v0.5.0 SOL-006a): integration tests for the
//! Solidity public-API surface extractor.
//!
//! Public surface for Solidity:
//!   - `function foo(...) external|public` → ApiKind::Function (or Method
//!     when inside a contract/interface/library).
//!   - `function foo(...) internal|private` → NOT in surface (unless
//!     `include_private=true`).
//!   - State variables with `public` visibility → auto-generated getter,
//!     surfaced as ApiKind::Property.
//!   - `event` declarations → ApiKind::Constant (observable surface).
//!   - `error` declarations (0.8.4+ custom errors) → ApiKind::Constant
//!     (part of the ABI).
//!   - Constructor → NOT in surface (one-time call).
//!   - Fallback / receive → surfaced as Method (externally invokable
//!     on raw `call`).
//!   - Modifiers → NOT in surface (not externally callable).
//!
//! Hermetic fixtures (no `/tmp/repos/...` dep) so tests are portable.

use std::fs;
use tempfile::TempDir;

use tldr_core::surface::{extract_api_surface, ApiKind};

const TOKEN_VAULT: &str = "\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Token vault
/// @notice A simple vault contract
contract TokenVault is Ownable, ReentrancyGuard {
    uint256 public totalDeposits;
    uint256 internal _internalCounter;
    address private _owner;

    event Deposit(address indexed user, uint256 amount);
    error InsufficientBalance(uint256 available, uint256 required);
    modifier nonReentrant() { _; }

    constructor() {}

    fallback() external payable {}
    receive() external payable {}

    /// @notice Deposit ether
    /// @param amount Amount to deposit
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

fn names(apis: &[tldr_core::surface::ApiEntry]) -> Vec<String> {
    apis.iter()
        .map(|a| a.qualified_name.rsplit('.').next().unwrap_or("").to_string())
        .collect()
}

// =============================================================================
// Public surface emission
// =============================================================================

#[test]
fn surface_includes_external_function() {
    let (_tmp, file) = write_fixture("TokenVault.sol", TOKEN_VAULT);
    let s = extract_api_surface(file.to_str().unwrap(), Some("solidity"), false, None, None)
        .expect("surface extraction should succeed");
    let n = names(&s.apis);
    assert!(
        n.iter().any(|x| x == "deposit"),
        "expected `deposit` (external) in surface; got {:?}",
        n
    );
}

#[test]
fn surface_includes_public_function() {
    let (_tmp, file) = write_fixture("TokenVault.sol", TOKEN_VAULT);
    let s = extract_api_surface(file.to_str().unwrap(), Some("solidity"), false, None, None)
        .expect("surface extraction should succeed");
    let n = names(&s.apis);
    assert!(
        n.iter().any(|x| x == "withdraw"),
        "expected `withdraw` (public) in surface; got {:?}",
        n
    );
}

#[test]
fn surface_excludes_internal_function() {
    let (_tmp, file) = write_fixture("TokenVault.sol", TOKEN_VAULT);
    let s = extract_api_surface(file.to_str().unwrap(), Some("solidity"), false, None, None)
        .expect("surface extraction should succeed");
    let n = names(&s.apis);
    assert!(
        !n.iter().any(|x| x == "_internalHelper"),
        "did NOT expect `_internalHelper` (internal) in surface; got {:?}",
        n
    );
}

#[test]
fn surface_excludes_private_function() {
    let (_tmp, file) = write_fixture("TokenVault.sol", TOKEN_VAULT);
    let s = extract_api_surface(file.to_str().unwrap(), Some("solidity"), false, None, None)
        .expect("surface extraction should succeed");
    let n = names(&s.apis);
    assert!(
        !n.iter().any(|x| x == "_privateHelper"),
        "did NOT expect `_privateHelper` (private) in surface; got {:?}",
        n
    );
}

#[test]
fn surface_includes_public_state_var_as_property() {
    let (_tmp, file) = write_fixture("TokenVault.sol", TOKEN_VAULT);
    let s = extract_api_surface(file.to_str().unwrap(), Some("solidity"), false, None, None)
        .expect("surface extraction should succeed");

    let entry = s
        .apis
        .iter()
        .find(|a| a.qualified_name.ends_with(".totalDeposits"));
    assert!(
        entry.is_some(),
        "expected `totalDeposits` (public state var → auto-getter) in surface; got names {:?}",
        names(&s.apis)
    );
    let entry = entry.unwrap();
    assert_eq!(
        entry.kind,
        ApiKind::Property,
        "expected public state var to surface as Property (auto-getter); got {:?}",
        entry.kind
    );
}

#[test]
fn surface_excludes_internal_state_var() {
    let (_tmp, file) = write_fixture("TokenVault.sol", TOKEN_VAULT);
    let s = extract_api_surface(file.to_str().unwrap(), Some("solidity"), false, None, None)
        .expect("surface extraction should succeed");
    assert!(
        !s.apis
            .iter()
            .any(|a| a.qualified_name.ends_with("._internalCounter")),
        "did NOT expect internal state var in surface"
    );
    assert!(
        !s.apis.iter().any(|a| a.qualified_name.ends_with("._owner")),
        "did NOT expect private state var in surface"
    );
}

#[test]
fn surface_includes_event() {
    let (_tmp, file) = write_fixture("TokenVault.sol", TOKEN_VAULT);
    let s = extract_api_surface(file.to_str().unwrap(), Some("solidity"), false, None, None)
        .expect("surface extraction should succeed");

    let entry = s
        .apis
        .iter()
        .find(|a| a.qualified_name.ends_with(".Deposit"));
    assert!(
        entry.is_some(),
        "expected event `Deposit` in surface; got names {:?}",
        names(&s.apis)
    );
}

#[test]
fn surface_includes_custom_error() {
    let (_tmp, file) = write_fixture("TokenVault.sol", TOKEN_VAULT);
    let s = extract_api_surface(file.to_str().unwrap(), Some("solidity"), false, None, None)
        .expect("surface extraction should succeed");

    let entry = s
        .apis
        .iter()
        .find(|a| a.qualified_name.ends_with(".InsufficientBalance"));
    assert!(
        entry.is_some(),
        "expected custom error `InsufficientBalance` in surface; got names {:?}",
        names(&s.apis)
    );
}

#[test]
fn surface_excludes_constructor() {
    let (_tmp, file) = write_fixture("TokenVault.sol", TOKEN_VAULT);
    let s = extract_api_surface(file.to_str().unwrap(), Some("solidity"), false, None, None)
        .expect("surface extraction should succeed");
    let n = names(&s.apis);
    assert!(
        !n.iter().any(|x| x == "constructor"),
        "did NOT expect `constructor` in surface (one-time call); got {:?}",
        n
    );
}

#[test]
fn surface_excludes_modifier() {
    let (_tmp, file) = write_fixture("TokenVault.sol", TOKEN_VAULT);
    let s = extract_api_surface(file.to_str().unwrap(), Some("solidity"), false, None, None)
        .expect("surface extraction should succeed");
    let n = names(&s.apis);
    assert!(
        !n.iter().any(|x| x == "nonReentrant"),
        "did NOT expect modifier `nonReentrant` in surface; got {:?}",
        n
    );
}

#[test]
fn surface_includes_fallback_and_receive() {
    let (_tmp, file) = write_fixture("TokenVault.sol", TOKEN_VAULT);
    let s = extract_api_surface(file.to_str().unwrap(), Some("solidity"), false, None, None)
        .expect("surface extraction should succeed");
    let n = names(&s.apis);
    assert!(
        n.iter().any(|x| x == "fallback"),
        "expected `fallback` in surface; got {:?}",
        n
    );
    assert!(
        n.iter().any(|x| x == "receive"),
        "expected `receive` in surface; got {:?}",
        n
    );
}

#[test]
fn surface_includes_contract_as_class() {
    let (_tmp, file) = write_fixture("TokenVault.sol", TOKEN_VAULT);
    let s = extract_api_surface(file.to_str().unwrap(), Some("solidity"), false, None, None)
        .expect("surface extraction should succeed");

    let entry = s
        .apis
        .iter()
        .find(|a| a.qualified_name.ends_with(".TokenVault"));
    assert!(
        entry.is_some(),
        "expected `TokenVault` in surface; got names {:?}",
        names(&s.apis)
    );
    let entry = entry.unwrap();
    assert_eq!(
        entry.kind,
        ApiKind::Class,
        "expected contract to surface as Class; got {:?}",
        entry.kind
    );
}

#[test]
fn surface_interface_classified_as_interface_kind() {
    const SRC: &str = "\
pragma solidity ^0.8.0;
interface IFoo {
    function bar(uint256 x) external returns (bool);
}
";
    let (_tmp, file) = write_fixture("IFoo.sol", SRC);
    let s = extract_api_surface(file.to_str().unwrap(), Some("solidity"), false, None, None)
        .expect("surface extraction should succeed");

    let entry = s
        .apis
        .iter()
        .find(|a| a.qualified_name.ends_with(".IFoo"));
    assert!(entry.is_some(), "expected `IFoo` in surface");
    assert_eq!(
        entry.unwrap().kind,
        ApiKind::Interface,
        "expected interface to surface as Interface kind"
    );
    // Interface functions are part of the public ABI.
    assert!(
        s.apis.iter().any(|a| a.qualified_name.ends_with(".bar")),
        "expected interface function `bar` in surface"
    );
}

#[test]
fn surface_library_classified_as_class_kind() {
    const SRC: &str = "\
pragma solidity ^0.8.0;
library SafeMath {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        return a + b;
    }
    function mul(uint256 a, uint256 b) public pure returns (uint256) {
        return a * b;
    }
}
";
    let (_tmp, file) = write_fixture("SafeMath.sol", SRC);
    let s = extract_api_surface(file.to_str().unwrap(), Some("solidity"), false, None, None)
        .expect("surface extraction should succeed");

    let entry = s
        .apis
        .iter()
        .find(|a| a.qualified_name.ends_with(".SafeMath"));
    assert!(entry.is_some(), "expected `SafeMath` in surface");
    // Library public fn surfaces; internal fn does not.
    assert!(
        s.apis.iter().any(|a| a.qualified_name.ends_with(".mul")),
        "expected library public fn `mul` in surface; got {:?}",
        names(&s.apis)
    );
    assert!(
        !s.apis.iter().any(|a| a.qualified_name.ends_with(".add")),
        "did NOT expect library internal fn `add` in surface"
    );
}

#[test]
fn surface_file_scope_free_function_included_when_external_or_public() {
    const SRC: &str = "\
pragma solidity ^0.8.0;
function topLevelHelper(uint256 x) pure returns (uint256) {
    return x + 1;
}
contract Foo {}
";
    let (_tmp, file) = write_fixture("FreeFn.sol", SRC);
    let s = extract_api_surface(file.to_str().unwrap(), Some("solidity"), false, None, None)
        .expect("surface extraction should succeed");
    // File-scope free functions in Solidity have no visibility keyword
    // (they're all externally callable). They should appear in surface.
    assert!(
        s.apis
            .iter()
            .any(|a| a.qualified_name.ends_with(".topLevelHelper")),
        "expected file-scope free function `topLevelHelper` in surface; got {:?}",
        names(&s.apis)
    );
}

#[test]
fn surface_include_private_flag_includes_internal_and_private() {
    let (_tmp, file) = write_fixture("TokenVault.sol", TOKEN_VAULT);
    let s = extract_api_surface(file.to_str().unwrap(), Some("solidity"), true, None, None)
        .expect("surface extraction should succeed");
    let n = names(&s.apis);
    assert!(
        n.iter().any(|x| x == "_internalHelper"),
        "expected `_internalHelper` in surface when include_private=true; got {:?}",
        n
    );
    assert!(
        n.iter().any(|x| x == "_privateHelper"),
        "expected `_privateHelper` in surface when include_private=true; got {:?}",
        n
    );
}

#[test]
fn surface_language_field_is_solidity() {
    let (_tmp, file) = write_fixture("TokenVault.sol", TOKEN_VAULT);
    let s = extract_api_surface(file.to_str().unwrap(), Some("solidity"), false, None, None)
        .expect("surface extraction should succeed");
    assert_eq!(s.language, "solidity");
}
