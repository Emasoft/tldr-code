//! solidity-ast-extract-v1 (v0.5.0 SOL-003): integration test for the
//! Solidity AST extraction layer.
//!
//! Covers the Phase 3 wiring of:
//!   - `extract_solidity_classes_detailed` → `ClassInfo` with
//!     `kind = Some("contract"|"interface"|"library")`
//!   - `extract_solidity_functions_detailed` →
//!     `FunctionInfo` with visibility / state_mutability /
//!     `modifier_invocations` (surfaced via `decorators`)
//!   - `build_solidity_modifier_info` → `ModifierInfo` (contract-scope)
//!   - `build_solidity_event_info` → `EventInfo` (per-param `indexed`)
//!   - `build_solidity_error_info` → `ErrorInfo` (typed params)
//!   - NatSpec `///` and `/** */` docstring preservation
//!   - `extract_solidity_class_bases` → flattened `is A, B` list
//!
//! Hermetic fixture (no `/tmp/repos/...` dep) so the test is portable.

use std::fs;
use tempfile::TempDir;

use tldr_core::ast::extract::extract_file_with_lang;
use tldr_core::types::Language;

/// Sample Solidity fixture covering every Phase 3 extraction kind:
/// - contract + inheritance specifiers (`is Ownable, ReentrancyGuard`)
/// - NatSpec `///` docstring on contract + on a function
/// - state variable (`uint256 public totalDeposits;`)
/// - event with one indexed + one non-indexed param
/// - custom error with two typed params (0.8.4+)
/// - modifier with empty params + body
/// - function with `external payable` + two modifier invocations +
///   `returns (bool)`
const FIXTURE: &str = "\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Token vault
/// @notice A simple vault contract
contract TokenVault is Ownable, ReentrancyGuard {
    uint256 public totalDeposits;
    event Deposit(address indexed user, uint256 amount);
    error InsufficientBalance(uint256 available, uint256 required);
    modifier nonReentrant() { _; }

    /// @notice Deposit ether
    /// @param amount Amount to deposit
    function deposit(uint256 amount) external payable onlyOwner nonReentrant returns (bool) {
        totalDeposits += amount;
        emit Deposit(msg.sender, amount);
        return true;
    }
}
";

fn write_fixture() -> (TempDir, std::path::PathBuf) {
    let tmp = TempDir::new().unwrap();
    let file = tmp.path().join("TokenVault.sol");
    fs::write(&file, FIXTURE).unwrap();
    (tmp, file)
}

#[test]
fn extract_emits_single_contract_class_with_correct_kind_and_bases() {
    let (_tmp, file) = write_fixture();
    let m = extract_file_with_lang(&file, None, Some(Language::Solidity))
        .expect("extract should succeed");

    assert_eq!(
        m.classes.len(),
        1,
        "expected exactly 1 class (the contract), got: {:?}",
        m.classes.iter().map(|c| &c.name).collect::<Vec<_>>()
    );
    let c = &m.classes[0];
    assert_eq!(c.name, "TokenVault");
    assert_eq!(c.kind.as_deref(), Some("contract"));
    assert_eq!(
        c.bases,
        vec!["Ownable".to_string(), "ReentrancyGuard".to_string()],
        "expected `is Ownable, ReentrancyGuard` to flatten into bases"
    );
}

#[test]
fn extract_emits_contract_natspec_docstring_verbatim() {
    let (_tmp, file) = write_fixture();
    let m = extract_file_with_lang(&file, None, Some(Language::Solidity)).unwrap();
    let c = &m.classes[0];
    let ds = c
        .docstring
        .as_ref()
        .expect("contract should have a NatSpec docstring");
    assert!(
        ds.contains("@title Token vault"),
        "docstring should preserve @title verbatim; got: {ds:?}"
    );
    assert!(
        ds.contains("@notice A simple vault contract"),
        "docstring should preserve @notice verbatim; got: {ds:?}"
    );
}

#[test]
fn extract_emits_function_with_visibility_state_mutability_and_modifiers() {
    let (_tmp, file) = write_fixture();
    let m = extract_file_with_lang(&file, None, Some(Language::Solidity)).unwrap();
    let c = &m.classes[0];
    assert_eq!(
        c.methods.len(),
        1,
        "expected exactly 1 method, got: {:?}",
        c.methods.iter().map(|f| &f.name).collect::<Vec<_>>()
    );
    let f = &c.methods[0];
    assert_eq!(f.name, "deposit");
    assert!(f.is_method, "deposit is a method of TokenVault");
    assert!(!f.is_async, "Solidity has no async");
    assert_eq!(
        f.visibility.as_deref(),
        Some("external"),
        "deposit declared `external`"
    );
    // state_mutability is encoded into decorators (leading slot), then
    // the modifier-invocations follow.
    assert!(
        f.decorators.contains(&"payable".to_string()),
        "expected state_mutability=`payable` in decorators; got: {:?}",
        f.decorators
    );
    assert!(
        f.decorators.contains(&"onlyOwner".to_string()),
        "expected `onlyOwner` modifier-invocation in decorators; got: {:?}",
        f.decorators
    );
    assert!(
        f.decorators.contains(&"nonReentrant".to_string()),
        "expected `nonReentrant` modifier-invocation in decorators; got: {:?}",
        f.decorators
    );
    assert_eq!(
        f.params,
        vec!["amount".to_string()],
        "deposit takes one named param"
    );
    assert_eq!(
        f.return_type.as_deref(),
        Some("bool"),
        "deposit returns bool"
    );
}

#[test]
fn extract_emits_function_natspec_docstring() {
    let (_tmp, file) = write_fixture();
    let m = extract_file_with_lang(&file, None, Some(Language::Solidity)).unwrap();
    let c = &m.classes[0];
    let f = &c.methods[0];
    let ds = f
        .docstring
        .as_ref()
        .expect("deposit should have a NatSpec docstring");
    assert!(
        ds.contains("@notice Deposit ether"),
        "deposit docstring should preserve @notice; got: {ds:?}"
    );
    assert!(
        ds.contains("@param amount Amount to deposit"),
        "deposit docstring should preserve @param; got: {ds:?}"
    );
}

#[test]
fn extract_emits_contract_scope_modifier() {
    let (_tmp, file) = write_fixture();
    let m = extract_file_with_lang(&file, None, Some(Language::Solidity)).unwrap();
    let c = &m.classes[0];
    assert_eq!(
        c.modifiers.len(),
        1,
        "expected exactly 1 contract-scope modifier; got: {:?}",
        c.modifiers.iter().map(|x| &x.name).collect::<Vec<_>>()
    );
    let md = &c.modifiers[0];
    assert_eq!(md.name, "nonReentrant");
    assert!(md.params.is_empty(), "nonReentrant() has no params");
    assert!(md.body_present, "modifier has a body");
    assert!(!md.is_virtual);
    assert!(!md.is_override);
    // File-scope module modifiers list should be empty (the modifier
    // is inside the contract).
    assert!(
        m.modifiers.is_empty(),
        "no file-scope modifiers in fixture; got: {:?}",
        m.modifiers.iter().map(|x| &x.name).collect::<Vec<_>>()
    );
}

#[test]
fn extract_emits_event_with_indexed_param() {
    let (_tmp, file) = write_fixture();
    let m = extract_file_with_lang(&file, None, Some(Language::Solidity)).unwrap();
    let c = &m.classes[0];
    assert_eq!(c.events.len(), 1, "expected exactly 1 event");
    let ev = &c.events[0];
    assert_eq!(ev.name, "Deposit");
    assert!(!ev.is_anonymous);
    assert_eq!(ev.params.len(), 2, "Deposit has 2 params");
    // First param: `address indexed user`.
    assert_eq!(ev.params[0].name, "user");
    assert_eq!(ev.params[0].type_, "address");
    assert!(ev.params[0].indexed, "first param `user` is indexed");
    // Second param: `uint256 amount` (non-indexed).
    assert_eq!(ev.params[1].name, "amount");
    assert_eq!(ev.params[1].type_, "uint256");
    assert!(
        !ev.params[1].indexed,
        "second param `amount` is NOT indexed"
    );
}

#[test]
fn extract_emits_custom_error_with_typed_params() {
    let (_tmp, file) = write_fixture();
    let m = extract_file_with_lang(&file, None, Some(Language::Solidity)).unwrap();
    let c = &m.classes[0];
    assert_eq!(c.errors.len(), 1, "expected exactly 1 custom error");
    let er = &c.errors[0];
    assert_eq!(er.name, "InsufficientBalance");
    assert_eq!(er.params.len(), 2);
    assert_eq!(er.params[0].name, "available");
    assert_eq!(er.params[0].type_.as_deref(), Some("uint256"));
    assert_eq!(er.params[1].name, "required");
    assert_eq!(er.params[1].type_.as_deref(), Some("uint256"));
}

#[test]
fn extract_emits_state_variable_as_class_field() {
    let (_tmp, file) = write_fixture();
    let m = extract_file_with_lang(&file, None, Some(Language::Solidity)).unwrap();
    let c = &m.classes[0];
    assert!(
        c.fields.iter().any(|f| f.name == "totalDeposits"),
        "expected state var `totalDeposits` in class fields; got: {:?}",
        c.fields.iter().map(|f| &f.name).collect::<Vec<_>>()
    );
    let f = c
        .fields
        .iter()
        .find(|f| f.name == "totalDeposits")
        .unwrap();
    assert_eq!(f.field_type.as_deref(), Some("uint256"));
    assert_eq!(f.visibility.as_deref(), Some("public"));
}

#[test]
fn extract_solidity_module_has_correct_language() {
    let (_tmp, file) = write_fixture();
    let m = extract_file_with_lang(&file, None, Some(Language::Solidity)).unwrap();
    assert_eq!(m.language, Language::Solidity);
    // No top-level functions (the only function is a contract member).
    assert!(
        m.functions.is_empty(),
        "expected zero file-scope functions; got: {:?}",
        m.functions.iter().map(|f| &f.name).collect::<Vec<_>>()
    );
    // No file-scope events/errors either.
    assert!(m.events.is_empty());
    assert!(m.errors.is_empty());
}

#[test]
fn extract_interface_kind_distinguished_from_contract() {
    let src = "\
pragma solidity ^0.8.0;
interface IFoo {
    function ping() external view returns (uint256);
}
contract Bar {}
library Util {}
";
    let tmp = TempDir::new().unwrap();
    let file = tmp.path().join("MultiKind.sol");
    fs::write(&file, src).unwrap();
    let m = extract_file_with_lang(&file, None, Some(Language::Solidity)).unwrap();
    assert_eq!(m.classes.len(), 3, "expected 3 top-level decls");

    let by_name: std::collections::HashMap<&str, &str> = m
        .classes
        .iter()
        .map(|c| (c.name.as_str(), c.kind.as_deref().unwrap_or("")))
        .collect();
    assert_eq!(by_name.get("IFoo"), Some(&"interface"));
    assert_eq!(by_name.get("Bar"), Some(&"contract"));
    assert_eq!(by_name.get("Util"), Some(&"library"));

    // The interface's `ping` should be a method with view state_mutability
    // in decorators.
    let i_foo = m.classes.iter().find(|c| c.name == "IFoo").unwrap();
    assert_eq!(i_foo.methods.len(), 1);
    let ping = &i_foo.methods[0];
    assert_eq!(ping.name, "ping");
    assert_eq!(ping.visibility.as_deref(), Some("external"));
    assert!(
        ping.decorators.contains(&"view".to_string()),
        "expected `view` state_mutability in decorators; got: {:?}",
        ping.decorators
    );
}

#[test]
fn extract_file_scope_constant_emits_constant_field() {
    let src = "\
pragma solidity ^0.8.0;
uint256 constant MAX_SUPPLY = 1000;
contract Foo {}
";
    let tmp = TempDir::new().unwrap();
    let file = tmp.path().join("Const.sol");
    fs::write(&file, src).unwrap();
    let m = extract_file_with_lang(&file, None, Some(Language::Solidity)).unwrap();
    assert!(
        m.constants.iter().any(|c| c.name == "MAX_SUPPLY"
            && c.is_constant
            && c.field_type.as_deref() == Some("uint256")),
        "expected `MAX_SUPPLY` as file-scope constant; got: {:?}",
        m.constants
    );
}
